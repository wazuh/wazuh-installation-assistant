#!/usr/bin/env python3
"""fleet-upgrade.py - upgrade a fleet of Wazuh 4.x agents to 5.0 from a 5.0 manager, in waves,
and decide the outcome of every agent from evidence instead of from the task status.

Experiment arm A1 of the 4.x -> 5.0 migration lab. Python standard library only.

  fleet-upgrade.py preflight   read-only: manager checks, per-agent checks, the wave plan
  fleet-upgrade.py run         request the next wave(s), verify, gate, repeat; safe to re-run
  fleet-upgrade.py status      re-verify every agent that has an open request, change nothing else
  fleet-upgrade.py report      print the final report from the state file

Why it exists: the 5.0 manager records no upgrade outcome (tasks stay 'delivered'), hands a task
to a 4.x agent only on a poll of up to 15 minutes, expires an undelivered task after task_ttl, and
runs the installer twice when it is asked twice. This tool keeps its own state file, never asks
twice while a request can still be alive, and classifies each agent from: the version and
keepalive the agent reports, and what remoted logged about the delivery and the agent's own result.

Every value an operator supplies is a named option (see --help); the password never goes on the
command line.
"""
import argparse
import base64
import datetime as dt
import fcntl
import json
import os
import re
import socket
import sqlite3
import ssl
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

TOOL_VERSION = "0.10-e3"        # an agent 'pending' right after the opening is waited for. 0.9-e2: E2 fold: certificate preflight per node. 0.8-merge: 0.7-a5 (over MAC1's 0.6-mac1 over AG1) + 0.6-a6 (over AG1)

# ---- product facts this tool depends on (source: wazuh/wazuh branch 5.0.0) --------------------
# task_manager/src/upgrade/platform.cpp
NO_WPK_PLATFORMS = {"solaris", "sunos", "aix", "hp-ux", "bsd"}
DEB_PLATFORMS = {"debian", "ubuntu"}
RPM_PLATFORMS = {"amzn", "centos", "fedora", "ol", "opensuse", "opensuse-leap", "opensuse-tumbleweed",
                 "rhel", "sles", "suse", "rocky", "almalinux"}
END_OF_LIFE = {("sles", "11"), ("suse", "11"), ("ol", "5"), ("rhel", "5"), ("centos", "5")}
MIN_DIRECT = (4, 14, 0)          # below this the manager answers 1819 for a 5.x target
# remoted/src/legacy_task_delivery.c
RETRY_LIST_MAX = 100             # in-memory retry list for pushes that got no answer
ACK_LIST_MAX = 1024              # agents that can be owed a clear_upgrade_result at once
# task_manager: largest request the module accepts (wazuh_modules.upgrade_max_agents)
UPGRADE_MAX_AGENTS = 500

TERMINAL_OK = {"upgraded", "upgraded-trust-unconfirmed", "upgraded-not-verifying", "already-target"}
TERMINAL_BAD = {"failed", "upgraded-not-connecting", "expired", "refused"}
# A5's host-gone and A6's no-answer-stale are both open states (different causes: a host that went away mid-sweep,
# against an agent silent past agents_disconnection_time whose push remoted refuses at once)
OPEN = {"requested", "delivering", "installing", "waiting-for-agent", "no-answer", "host-gone", "no-answer-stale"}
TERMINAL_BAD.add("dropped")
RESPONSE_TIMEOUT = 60            # remoted.response_timeout: what one silent agent costs the single delivery thread
STALE_KEEPALIVE = 180            # (ag1) an "active" agent whose last keepalive is older than this is not answering
# (a5) trust is part of the verdict, not a footnote to it: only a proven upgrade releases an operating system's lane,
# an agent proven to verify nothing counts against the failure brake, and both trust states are re-read every pass
# so that an endpoint fix (wazuh-agent-auth --certs-only) is seen without a new request
VERIFIED_OK = {"upgraded", "already-target"}
TRUST_BAD = {"upgraded-not-verifying"}
TRUST_OPEN = {"upgraded-not-verifying", "upgraded-trust-unconfirmed"}
# (a5) states that keep an operating system's batch open: the next batch of that lane is requested only when none
# of its agents is in one of these, so the brake always judges a whole batch before more tasks exist (a task cannot
# be cancelled). no-answer and waiting-for-agent are parked, not open: remoted holds them, and they must not stall a lane
# (merged: no-answer-stale and host-gone are parked the same way)
LANE_BUSY = {"requested", "delivering", "installing"}
# (a6) measured in arm A6 at the product defaults (see its SCORECARD):
RETRY_MAX_AGE = 3600             # legacy_task_delivery.c: a no-answer task stays in the retry list this long from its first
                                 # no-answer push, and is purged (debug log only) at the start of the first cycle after that
CLEANUP_INTERVAL = 300           # task manager <cleanup_interval>: a pending task older than task_ttl turns 'expired' at the next pass
DISCONNECTION_TIME = 900         # <global><agents_disconnection_time>: remoted refuses at once to send to a 4.x agent silent for
                                 # longer (ERROR "cannot send request to agent"), so such an agent costs the thread nothing
FRESH_SILENT_PRIOR = 0.05        # share of pushed agents that keep their session and do not answer, until this run measured it


def now():
    return time.time()


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else "-"


def parse_ts(s):
    """API timestamps: 2026-11-22T13:07:14+00:00 or ...Z. Returns epoch or 0."""
    if not s or s.startswith("9999"):
        return 0
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0


def vtuple(v):
    """'Wazuh v4.14.10' / 'v5.0.0' -> (4, 14, 10); unknown -> None."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def log(msg):
    print(f"{iso(now())} {msg}", flush=True)


# ---- API client --------------------------------------------------------------------------------
class Api:
    def __init__(self, url, user, password, ca=None, insecure=False):
        self.url, self.user, self.password = url.rstrip("/"), user, password
        self.ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context(cafile=ca)
        self.token, self.token_at = None, 0

    # The manager is restarted during a migration (certificate reissue, configuration change): a
    # refused or dropped connection is waited out instead of ending the run. A PUT is never repeated
    # after the request may have reached the manager: that would be a second upgrade request.
    OUTAGE_PATIENCE = 600

    def _auth(self):
        req = urllib.request.Request(self.url + "/security/user/authenticate?raw=true", method="POST")
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{self.user}:{self.password}".encode()).decode())
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
            self.token, self.token_at = r.read().decode().strip(), now()

    def call(self, method, path, params=None, timeout=300):
        q = ("?" + urllib.parse.urlencode(params, safe=",<>=;~!")) if params else ""
        t0, reauth, warned = now(), 0, False
        while True:
            sent = False
            try:
                if not self.token or now() - self.token_at > 600:
                    self._auth()
                req = urllib.request.Request(self.url + path + q, method=method)
                req.add_header("Authorization", "Bearer " + self.token)
                sent = True
                with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as r:
                    return r.status, json.loads(r.read().decode() or "{}")
            except urllib.error.HTTPError as e:
                body = e.read().decode()
                if e.code == 401 and reauth < 2:
                    reauth += 1
                    self.token = None
                    continue
                try:
                    return e.code, json.loads(body)
                except ValueError:
                    return e.code, {"raw": body}
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                refused = "refused" in str(e).lower() or "111" in str(e)
                if method != "GET" and sent and not refused:
                    return 0, {"detail": f"connection lost after the request was sent ({e}); outcome unknown, not repeated"}
                if now() - t0 > self.OUTAGE_PATIENCE:
                    raise
                if not warned:
                    log(f"manager API not answering ({e}); waiting up to {self.OUTAGE_PATIENCE}s")
                    warned = True
                time.sleep(5)

    def items(self, path, params=None):
        """All affected_items of a paged GET."""
        out, offset, params = [], 0, dict(params or {})
        while True:
            params.update(limit=500, offset=offset)
            code, r = self.call("GET", path, params)
            if code != 200:
                raise RuntimeError(f"GET {path} -> {code}: {json.dumps(r)[:300]}")
            page = r["data"]["affected_items"]
            out += page
            offset += len(page)
            if not page or offset >= r["data"].get("total_affected_items", 0):
                return out


# ---- what the manager knows --------------------------------------------------------------------
def manager_facts(api):
    code, root = api.call("GET", "/")
    f = {"version": "v" + root["data"]["api_version"], "revision": root["data"].get("revision"),
         "hostname": root["data"].get("hostname"), "nodes": {}}
    for n in api.items("/cluster/nodes"):
        name = n["name"]
        node = {"type": n.get("type"), "version": n.get("version"), "ip": n.get("ip")}
        c, r = api.call("GET", f"/cluster/{name}/configuration/request/remote")
        node["remote"] = r["data"]["affected_items"][0]["remote"] if c == 200 and r.get("data", {}).get("affected_items") else {"error": r}
        c, r = api.call("GET", f"/cluster/{name}/configuration/request/internal")
        node["poll_interval"] = (r["data"]["affected_items"][0]["internal"]["remoted"].get("legacy_task_polling_interval")
                                 if c == 200 and r.get("data", {}).get("affected_items") else None)
        c, r = api.call("GET", f"/cluster/{name}/configuration/wmodules/wmodules")
        node["task_manager"] = {}
        if c == 200 and r.get("data", {}).get("affected_items"):
            for m in r["data"]["affected_items"][0].get("wmodules", []):
                if "task-manager" in m:
                    node["task_manager"] = m["task-manager"]
        c, r = api.call("GET", f"/cluster/{name}/daemons/remoted/tls")
        node["tls"] = r["data"]["affected_items"][0] if c == 200 and r.get("data", {}).get("affected_items") else {"available": False, "reason": str(r)[:200]}
        c, r = api.call("GET", f"/cluster/{name}/daemons/stats", {"daemons_list": "wazuh-manager-remoted"})
        try:
            m = r["data"]["affected_items"][0]["metrics"]
            node["legacy_tcp_sessions"] = m.get("tcp_sessions")
            node["upgrade_acks"] = m["messages"]["received_breakdown"].get("upgrade_ack")
        except (KeyError, IndexError, TypeError):
            node["legacy_tcp_sessions"] = None
        f["nodes"][name] = node
    return f


def fleet(api, agents=None, groups=None):
    params = {"select": "id,name,version,status,group,ip,registerIP,lastKeepAlive,dateAdd,"
                        "os.platform,os.name,os.version,os.major,os.minor,os.arch", "sort": "+id"}
    if agents:
        params["agents_list"] = ",".join(agents)
    out = [a for a in api.items("/agents", params) if a["id"] != "000"]
    if groups:
        out = [a for a in out if set(a.get("group") or []) & set(groups)]
    return out


PENDING_WAIT = 120               # E3-deb N5: seconds to wait for agents the manager lists as 'pending'


def fleet_settled(api, a, _sleep=None, _clock=None, _now=None):
    """E3-deb N5: right after the opening an agent can be 'pending' for a while (connected, its session with the new
    manager not complete: the Windows agent was re-applying the new shared configuration 46 s after the opening) and was
    skipped as if disconnected. Read the fleet again every 10 s, up to --pending-wait seconds, while any agent is
    pending. Returns (agents, the ids still pending, seconds waited).
    E4-deb N-F5: an agent the manager lists as 'disconnected' whose last keepalive is recent (within the same wait) is
    waited for the same way: 27 s after the opening the Windows agent read 'active' at the preflight and 'disconnected'
    one second later at the run step (it was re-applying its new group files) and was skipped until a second call. One
    still disconnected after the wait is named, then planned as before (skipped, re-run when it is back).
    _now: epoch seconds (tests)."""
    _sleep, _clock = _sleep or time.sleep, _clock or time.monotonic
    wait = getattr(a, "pending_wait", None)
    wait = PENDING_WAIT if wait is None else int(wait)
    agents, t0, said = fleet(api, a.agents, a.groups), _clock(), set()

    def recent(x):
        try:
            k = dt.datetime.fromisoformat(str(x.get("lastKeepAlive") or "").replace("Z", "+00:00")).timestamp()
        except ValueError:
            return False
        return (_now() if _now else time.time()) - k <= wait

    while True:
        pend = [x["id"] for x in agents if x.get("status") == "pending"]
        flap = [x["id"] for x in agents if x.get("status") == "disconnected" and recent(x)]
        if not (pend or flap) or _clock() - t0 >= wait:
            if flap and "flap" in said:
                log(f"agent(s) {','.join(flap)} still 'disconnected' after {int(_clock() - t0)}s (their last keepalive was recent): "
                    "planned as disconnected; run the agents step again once they are back")
            return agents, pend + flap, int(_clock() - t0)
        if pend and "pend" not in said:
            log(f"agent(s) {','.join(pend)} 'pending' (connected, the session with this manager not complete yet): "
                f"waiting up to {wait}s for them before planning")
            said.add("pend")
        if flap and "flap" not in said:
            log(f"agent(s) {','.join(flap)} 'disconnected' with a keepalive in the last {wait}s (reconnecting after the opening, "
                f"or reloading their group files): waiting up to {wait}s for them before planning")
            said.add("flap")
        _sleep(10)
        agents = fleet(api, a.agents, a.groups)


def read_logs(api, node, since, local_log=None):
    """remoted's legacy_task_delivery lines newer than `since` (epoch), oldest first.
    Source: the node's log through the API (the API serves only the newest entries of the file), or
    the log file itself with --manager-log when the tool runs on the manager."""
    out = []
    if local_log:
        # (a6) also accept the format remoted writes when its debug option is on: "<daemon>[pid] file.c:N at func(): LEVEL: text"
        rx = re.compile(r"^(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d) (.+?): (DEBUG|INFO|WARNING|ERROR|CRITICAL): (.*)$")
        with open(local_log, errors="replace") as fh:
            for line in fh:
                if "legacy_task_delivery" not in line and "cannot send request to agent" not in line:
                    continue
                m = rx.match(line.rstrip("\n"))
                if not m:
                    continue
                if m.group(8) == "DEBUG":
                    continue        # (a6) the lab runs remoted with debug on; an operator's log has no DEBUG lines
                y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
                # the manager writes local time; the lab hosts run in UTC
                ts = dt.datetime(y, mo, d, h, mi, s, tzinfo=dt.timezone.utc).timestamp() - LOG_UTC_OFFSET
                if ts >= since:
                    out.append({"t": ts, "level": m.group(8).lower(), "text": m.group(9)})
        return out
    for search in ("legacy_task_delivery", "cannot send request to agent"):   # (a6) the refusal line has no prefix
        offset = 0
        while True:
            c, r = api.call("GET", f"/cluster/{node}/logs", {"search": search, "limit": 500,
                                                               "offset": offset, "sort": "-timestamp"})
            if c != 200:
                raise RuntimeError(f"cannot read logs of {node}: {c} {str(r)[:200]}")
            page = r["data"]["affected_items"]
            for e in page:
                ts = parse_ts(e["timestamp"])
                if ts >= since:
                    out.append({"t": ts, "level": e["level"], "text": e["description"]})
            offset += len(page)
            if not page or offset >= r["data"]["total_affected_items"] or parse_ts(page[-1]["timestamp"]) < since:
                break
    return sorted(out, key=lambda e: e["t"])


LOG_UTC_OFFSET = 0

RX = {
    "delivering": re.compile(r"delivering remote_upgrade task '([^']+)' to agent '(\d+)' \(wpk: '([^']+)'\)"),
    "delivered": re.compile(r"successfully delivered remote_upgrade task '([^']+)' to agent '(\d+)' \(wpk: '([^']+)'\)"),
    "ca_ok": re.compile(r"agent '(\d+)': delivered the manager CA as '[^']+' for task '([^']+)'"),
    "ca_fail": re.compile(r"agent '(\d+)': (could not deliver the manager CA.*|the configured CA .*|the certificate this manager serves.*)"),
    "result": re.compile(r"agent '(\d+)' reported upgrade result \(error (-?\d+): (.*)\), replying"),
    "installer_failed": re.compile(r"agent '(\d+)': installer script failed \(exit status: (.*)\)"),
    "push_failed": re.compile(r"agent '(\d+)': ('upgrade' step failed|'[a-z_0-9]+' step failed, aborting push|"
                              r"sha1 mismatch.*|cannot open local WPK file.*|task '[^']+' did not succeed after.*|"
                              r"invalid or incomplete remote_upgrade payload.*|no response for step.*|rejected step.*)"),
    "poller": re.compile(r"poller thread started \(startup delay (\d+)s, poll interval (\d+)s\)"),
    # (ag1) a push that got no answer at all goes to remoted's in-memory retry list (100 entries, 3600 s); when
    # the list is full the OLDEST entry is dropped with this warning, and its task is lost for good
    "retry_dropped": re.compile(r"retry list full \((\d+) entries\), dropping oldest task '([^']+)' for agent '(\d+)'"),
    # (a6) an agent silent for longer than agents_disconnection_time: remoted does not send, the push fails at once (ERROR),
    # the task still goes to the retry list, and the attempt costs the delivery thread nothing
    "refused_stale": re.compile(r"req_send_and_wait\(\): cannot send request to agent '(\d+)'"),
}


def index_logs(lines):
    """Per agent, the delivery events found in the log lines."""
    by = {}
    for e in lines:
        t = e["text"]
        for kind, rx in RX.items():
            m = rx.search(t)
            if not m:
                continue
            if kind in ("delivering", "delivered"):
                aid, ev = m.group(2), {"kind": kind, "t": e["t"], "task": m.group(1), "wpk": m.group(3)}
            elif kind == "ca_ok":
                aid, ev = m.group(1), {"kind": kind, "t": e["t"], "task": m.group(2)}
            elif kind == "result":
                aid, ev = m.group(1), {"kind": kind, "t": e["t"], "error": int(m.group(2)), "message": m.group(3)}
            elif kind == "retry_dropped":
                aid, ev = m.group(3), {"kind": kind, "t": e["t"], "task": m.group(2)}
            elif kind == "refused_stale":
                aid, ev = m.group(1), {"kind": kind, "t": e["t"]}
            elif kind == "poller":
                aid, ev = "_manager", {"kind": kind, "t": e["t"], "interval": int(m.group(2)), "delay": int(m.group(1))}
            else:
                aid, ev = m.group(1), {"kind": kind, "t": e["t"], "detail": m.group(2)}
            by.setdefault(aid, []).append(ev)
            break
    return by


class Indexer:
    """Optional second source. A 5.0 agent reports its resolved configuration, and the manager indexes
    it in wazuh-agent-config: the TLS verification mode the agent really runs with and the address it
    dials are there. The manager API does not serve this index."""

    def __init__(self, url, user, password, ca=None, insecure=False):
        self.url, self.auth = url.rstrip("/"), base64.b64encode(f"{user}:{password}".encode()).decode()
        self.ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context(cafile=ca)

    def tls_modes(self, ids=None):
        """{agent id: {"mode": ..., "ca": ..., "dials": [...], "reported": ...}}"""
        body = {"size": 10000, "_source": ["wazuh.agent.id", "wazuh.agent.version", "state.modified_at",
                                           "wazuh.agent.configuration.content.agent.agent.ssl",
                                           "wazuh.agent.configuration.content.agent.agent.manager"]}
        if ids:
            body["query"] = {"terms": {"wazuh.agent.id": list(ids)}}
        req = urllib.request.Request(self.url + "/wazuh-agent-config/_search", method="POST", data=json.dumps(body).encode())
        req.add_header("Authorization", "Basic " + self.auth)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
            hits = json.loads(r.read().decode())["hits"]["hits"]
        out = {}
        for h in hits:
            src = h["_source"]
            ag = src.get("wazuh", {}).get("agent", {})
            cfg = ag.get("configuration", {}).get("content", {}).get("agent", {}).get("agent", {})
            mgr = cfg.get("manager") or []
            mgr = mgr if isinstance(mgr, list) else [mgr]
            out[ag.get("id")] = {"mode": (cfg.get("ssl") or {}).get("verification_mode"),
                                 "ca": (cfg.get("ssl") or {}).get("certificate_authorities"),
                                 "dials": [m.get("address") for m in mgr if m.get("address")],
                                 "reported": parse_ts((src.get("state") or {}).get("modified_at"))}
        return out


INDEXER = None


def progress_line(play, open_left, st, leave, sweep, t):
    """The run's line at least every minute (E8-cluster-deb 7, E9-aio U9): every agent it waits for, with when its
    request is due (the request plus one poll of the manager, and the sweep), and when an agent that is not connected
    is left for a later run (once the others are done, then --leave-disconnected seconds)."""
    poll = st.get("poll_interval") or 900

    def by(i):
        r = (play[i].get("requests") or [{}])[-1]
        return r["t"] + poll + sweep if r.get("t") else None

    def say(i):
        r = (play[i].get("requests") or [{}])[-1]
        if play[i]["state"] == "waiting-for-agent":
            return "%s (%s) not connected: upgraded once it connects" % (i, play[i].get("name", ""))
        return ("%s (%s) %s, requested %ss ago, due by %s" % (i, play[i].get("name", ""), play[i]["state"], int(t - r["t"]), iso(by(i)))
                if r.get("t") else "%s (%s) %s" % (i, play[i].get("name", ""), play[i]["state"]))
    dues = [by(i) for i in open_left if play[i]["state"] != "waiting-for-agent" and by(i)]
    gone = [i for i in open_left if play[i]["state"] == "waiting-for-agent"]
    tail = ""
    if gone and dues:
        tail = ("; not connected (%s): left for a later run once the others are done (by %s at the latest), then %ss more"
                % (", ".join(gone), iso(max(dues)), leave))
    elif gone:
        tail = "; not connected: left for a later run at %s" % iso(st.get("parked_since", t) + leave)
    return ("waiting for %d agent(s): %s; the manager offers an upgrade to a 4.x agent on its poll, every %ss%s"
            % (len(open_left), "; ".join(say(i) for i in open_left[:20]), poll, tail))


def pending_tasks_from_db(path):
    """Optional, local only: agents that still have a pending remote_upgrade task in tasks.db.
    The module owns the live file, so a copy is queried, as the product documentation says."""
    d = tempfile.mkdtemp(prefix="fleet-upgrade-")
    try:
        for suffix in ("", "-wal"):
            if os.path.exists(path + suffix):
                shutil.copy(path + suffix, os.path.join(d, "tasks.db" + suffix))
        con = sqlite3.connect(os.path.join(d, "tasks.db"))
        cols = [r[1].lower() for r in con.execute("PRAGMA table_info(TASKS)")]
        rows = con.execute("SELECT * FROM TASKS").fetchall()
        out = {}
        for r in rows:
            row = dict(zip(cols, r))
            if str(row.get("task_type")) == "remote_upgrade" and str(row.get("status")) == "pending":
                out.setdefault(str(row.get("agent_id")).zfill(3), []).append(row)
        return out
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---- WPK repository ----------------------------------------------------------------------------
def package_family(platform, os_major):
    if platform in NO_WPK_PLATFORMS:
        return None, "the manager has no upgrade package for this platform (solaris, aix, hp-ux, bsd)"
    if (platform, str(os_major)) in END_OF_LIFE:
        return None, "operating system release is end of life for remote upgrade"
    if platform == "windows":
        return "msi", None
    if platform == "darwin":
        return "pkg", None
    if platform in DEB_PLATFORMS:
        return "deb", None
    if platform in RPM_PLATFORMS:
        return "rpm", None
    return None, f"distribution '{platform}' is not in the manager's deb/rpm tables; the request needs package_type"


def wpk_location(repo, platform, arch, family, version):
    """Where the manager looks for the WPK of a >= 4.9 target (task_manager/src/upgrade/repoLayout.cpp)."""
    repo = repo if "://" in repo else "https://" + repo
    repo = repo if repo.endswith("/") else repo + "/"
    if platform == "windows":
        return repo + "windows/", f"wazuh_agent_{version}_windows.wpk"
    if platform == "darwin":
        a = {"x86_64": "intel64", "aarch64": "arm64"}.get(arch, arch)
        return repo + f"macos/pkg/{a}/", f"wazuh_agent_{version}_macos_{a}.pkg.wpk"
    a = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch) if family == "deb" else arch
    return repo + f"linux/{family}/{a}/", f"wazuh_agent_{version}_linux_{a}.{family}.wpk"


_versions_cache = {}


def repo_has(repo, platform, arch, family, version, timeout=20):
    """(True|False|None, detail): does <path>/versions list the version? None = could not ask."""
    path, fname = wpk_location(repo, platform, arch, family, version)
    if path not in _versions_cache:
        box = {}

        def ask():
            try:
                req = urllib.request.Request(path + "versions", headers={"User-Agent": "fleet-upgrade/" + TOOL_VERSION})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    box["r"] = ("ok", r.read().decode(errors="replace"))
            except urllib.error.HTTPError as e:
                box["r"] = ("http", str(e.code))
            except Exception as e:  # noqa: BLE001 - any network failure is the same answer here
                box["r"] = ("net", str(e))

        # one overall limit: a name with several unreachable addresses would otherwise cost one
        # timeout per address and stall the whole preflight
        th = threading.Thread(target=ask, daemon=True)
        th.start()
        th.join(timeout + 5)
        _versions_cache[path] = box.get("r", ("net", f"no answer in {timeout + 5}s"))
    kind, body = _versions_cache[path]
    if kind == "ok":
        listed = [l.split()[0] for l in body.splitlines() if l.strip()]
        return (version in listed), f"{path}versions lists {', '.join(listed[:4]) or 'nothing'}"
    if kind == "http":
        return False, f"{path}versions -> HTTP {body}"
    return None, f"{path}versions not reachable from this host: {body}"


def latest_listed(repo, platform, arch, family, prefix):
    path, _ = wpk_location(repo, platform, arch, family, "x")
    repo_has(repo, platform, arch, family, "x")
    kind, body = _versions_cache.get(path, ("net", ""))
    if kind != "ok":
        return None
    c = [l.split()[0] for l in body.splitlines() if l.strip() and l.split()[0].startswith(prefix)]
    return max(c, key=lambda v: vtuple(v) or (0, 0, 0)) if c else None


# ---- certificate coverage ----------------------------------------------------------------------
def san_covers(sans, address):
    address = address.lower().strip("[]")
    for s in sans:
        s = s.lower()
        if s == address:
            return True
        if s.startswith("*.") and "." in address and address.split(".", 1)[1] == s[2:]:
            return True
    return False


def nodes_reached(addr, nodes, node_addresses=None, resolve=True):
    """E2-cluster gap 5: the manager nodes an agent that dials `addr` can reach. One node when the address is that node's
    own: its name, its cluster address (/cluster/nodes "ip"), an address given with --node-address NODE=ADDR, or a name
    that resolves only to that node's address. Every node otherwise: a balancer, or a name the nodes share, can hand the
    agent to any of them. Before this, every node's certificate had to carry every dialled address, which only holds
    behind a balancer whose name every node carries; in a cluster without one (each agent dials its own node) the preflight skipped every agent and the upgrade needed --allow-cert-mismatch."""
    a = addr.lower().strip("[]")
    own = {}
    for name, n in nodes.items():
        own[name] = {name.lower(), str(n.get("ip") or "").lower()} | {x.lower() for x in (node_addresses or {}).get(name, [])}
        own[name].discard("")
    hit = [name for name, s in own.items() if a in s]
    if len(hit) == 1:
        return hit
    if resolve and not hit:
        ips = _resolve(a)
        hit = [name for name, s in own.items() if ips and ips <= s]
        if len(hit) == 1:
            return hit
    return sorted(nodes)


_RESOLVED = {}


def _resolve(name):
    """Addresses a name resolves to from this host, looked up once per run (a fleet dials few names)."""
    if name not in _RESOLVED:
        try:
            _RESOLVED[name] = frozenset(i[4][0].lower() for i in socket.getaddrinfo(name, None))
        except (OSError, UnicodeError):
            _RESOLVED[name] = frozenset()
    return _RESOLVED[name]


def cert_missing(addr, sans_by_node, nodes, node_addresses=None, resolve=True):
    """The reachable nodes (nodes_reached) whose listener certificate does not carry `addr`."""
    return [n for n in nodes_reached(addr, nodes, node_addresses, resolve) if n in sans_by_node and not san_covers(sans_by_node[n], addr)]


def parse_node_addresses(items):
    out = {}
    for it in items or []:
        node, _, addr = it.partition("=")
        if node and addr:
            out.setdefault(node, []).append(addr)
    return out


def probe_listener(host, port, prefix="/wazuh-manager/"):
    """Is the HTTPS agent listener answering its liveness route from where this tool runs?"""
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                t.sendall(f"GET {prefix} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                data = t.recv(2048).decode(errors="replace")
                return ('"status":"ok"' in data.replace(" ", "")), data.splitlines()[0] if data else "no answer", t.version()
    except Exception as e:  # noqa: BLE001
        return False, str(e), None


# ---- preflight ---------------------------------------------------------------------------------
def preflight(api, a, facts_4x):
    mf = manager_facts(api)
    target = a.target or mf["version"]
    problems, warnings, notes = [], [], []
    polls, ttls, sans_by_node, legacy_off = [], [], {}, []
    ca_off = []  # mac1: nodes with <legacy><ca_delivery> off
    for name, n in mf["nodes"].items():
        r = n["remote"]
        if "error" in r:
            problems.append(f"node {name}: the remote configuration cannot be read")
            continue
        leg, https = r.get("legacy", {}), r.get("https", {})
        if not leg.get("enabled"):
            legacy_off.append(name)
        if https.get("bind_addr") in ("127.0.0.1", "::1", "localhost"):
            problems.append(f"node {name}: the HTTPS agent listener is bound to {https.get('bind_addr')}; upgraded agents cannot reach port {https.get('port')}")
        vm = https.get("verification_mode")
        if (vm and vm != "none") or (https.get("ca") and not vm):
            problems.append(f"node {name}: <remote><https><verification_mode> resolves to '{vm or 'certificate'}'; upgrades to 5.x are refused (task manager error 16)")
        if leg.get("ca_delivery") is False:
            ca_off.append(name)
            warnings.append(f"node {name}: <legacy><ca_delivery> is off; every upgraded agent comes up without a trust anchor unless one is already on the host")
        tm = n.get("task_manager", {})
        if str(tm.get("agent_upgrade", {}).get("enabled", "yes")) == "no":
            problems.append(f"node {name}: <task-manager><upgrade_enabled> is no")
        if tm.get("agent_upgrade", {}).get("wpk_repository"):
            notes.append(f"node {name}: <wpk_repository> is set to {tm['agent_upgrade']['wpk_repository']}; it applies to every target version, the 4.14.x step included, unless a request names wpk_repo")
        if n.get("poll_interval"):
            polls.append(n["poll_interval"])
        if tm.get("task_ttl"):
            ttls.append(tm["task_ttl"])
        tls = n.get("tls", {})
        if not tls.get("available"):
            problems.append(f"node {name}: remoted does not report its TLS state ({tls.get('reason', '?')})")
        else:
            sans_by_node[name] = tls["listener"].get("sans", [])
            cb = tls.get("ca_bundle", {})
            if not cb.get("chain_valid") or not cb.get("matches_active_leaf"):
                problems.append(f"node {name}: the CA remoted hands out does not sign the certificate it serves; an agent that pins it refuses the manager")
            if tls["listener"].get("seconds_until_expiry", 1) < 30 * 86400:
                warnings.append(f"node {name}: the listener certificate expires in {tls['listener'].get('seconds_until_expiry', 0) // 86400} days")
        ok, detail, tlsv = probe_listener(a.listener_host or urllib.parse.urlparse(a.api).hostname, https.get("port", 1517), https.get("global_prefix", "/wazuh-manager/"))
        (notes if ok else problems).append(f"node {name}: port {https.get('port', 1517)} liveness from this host: {'ok' if ok else 'FAILED'} ({detail}{', ' + tlsv if tlsv else ''})")
    poll = a.poll_interval or (max(polls) if polls else 900)
    ttl = min(ttls) if ttls else 3600
    if poll * 2 > ttl:
        warnings.append(f"legacy_task_polling_interval ({poll}s) is more than half of task_ttl ({ttl}s): a task can expire before it is offered")

    repo5 = a.wpk_repo or next((n["task_manager"].get("agent_upgrade", {}).get("wpk_repository") for n in mf["nodes"].values()
                                if n.get("task_manager", {}).get("agent_upgrade", {}).get("wpk_repository")), None) \
        or f"packages.wazuh.com/{vtuple(target)[0]}.x/wpk/"
    repo4 = a.step_wpk_repo or "packages.wazuh.com/4.x/wpk/"

    (agents, still_pending, waited), plan = fleet_settled(api, a), {}
    dialed_all = {}
    for ag in agents:
        aid, osd = ag["id"], ag.get("os") or {}
        platform, arch, v = osd.get("platform", ""), osd.get("arch", ""), vtuple(ag.get("version"))
        fx = (facts_4x or {}).get(aid, {})
        e = {"name": ag["name"], "version": ag.get("version"), "status": ag.get("status"), "platform": platform,
             "os": f"{osd.get('name', '?')} {osd.get('version', '')}".strip(), "arch": arch, "groups": ag.get("group") or [],
             "lastKeepAlive": ag.get("lastKeepAlive"), "skip": None, "warn": [], "steps": [], "dialed": fx.get("dialed", [])}
        tt = vtuple(target)
        if v is None:
            e["skip"] = "no version on record (the agent never reported to this manager); nothing to upgrade from"
        elif v >= tt:
            e["skip"] = "already-target"
        elif v < (3, 0, 0):
            e["skip"] = "agent below v3.0.0: not upgradable remotely (error 1820)"
        fam, why = package_family(platform, osd.get("major"))
        if not e["skip"] and not arch:
            e["skip"] = "the manager has no architecture for this agent; it cannot choose a package"
        if not e["skip"] and fam is None:
            if a.package_type and platform not in NO_WPK_PLATFORMS:
                fam = a.package_type
                e["warn"].append(f"{why}; using --package-type {fam}")
            else:
                e["skip"] = why
        if not e["skip"]:
            e["family"] = fam
            has, detail = repo_has(repo5, platform, arch, fam, target)
            if has is False:
                e["skip"] = f"no {target} agent package for {platform}/{arch} ({detail})"
            elif has is None:
                e["warn"].append(f"could not confirm the {target} package from here ({detail})")
            if v < MIN_DIRECT and not e["skip"]:
                step = a.step_version or latest_listed(repo4, platform, arch, fam, "v4.14.")
                if not step:
                    e["skip"] = f"agent is below v4.14.0 and no 4.14.x package was found for {platform}/{arch} in {repo4}"
                else:
                    e["steps"].append({"version": step, "repo": repo4})
            e["steps"].append({"version": target, "repo": repo5})
        if not e["skip"] and ag.get("status") == "active" and parse_ts(ag.get("lastKeepAlive")) and \
                now() - parse_ts(ag.get("lastKeepAlive")) > STALE_KEEPALIVE and not a.include_stale:
            e["skip"] = (f"agent is 'active' but its last keepalive is {int(now() - parse_ts(ag.get('lastKeepAlive')))}s old: an agent that does "
                         f"not answer costs remoted's single delivery thread {RESPONSE_TIMEOUT}s per attempt and holds a retry-list slot; "
                         "re-run when it reports again (--include-stale to request it anyway)")
        if not e["skip"] and ag.get("status") == "pending" and not a.include_disconnected:
            e["skip"] = (f"agent is pending after {waited}s of waiting (connected, but its session with this manager is not complete; "
                         "right after the opening it may still be applying the new shared configuration): run the agents phase "
                         "again once it is active")
        if not e["skip"] and ag.get("status") != "active":
            if not a.include_disconnected:
                e["skip"] = f"agent is {ag.get('status')}: a task waits at most task_ttl ({ttl}s) and then expires; re-run when it is back"
            else:
                e["warn"].append(f"agent is {ag.get('status')}: requested anyway (--include-disconnected); the task expires after {ttl}s")
        # the certificate against the address this agent dials
        if not e["skip"]:
            if not e["dialed"]:
                e["warn"].append("the address this agent dials is unknown (no 4.x fleet facts): certificate coverage NOT checked")
            for addr in e["dialed"]:
                dialed_all.setdefault(addr, []).append(aid)
                # only the nodes this address can reach must carry it
                missing = cert_missing(addr, sans_by_node, mf["nodes"], parse_node_addresses(getattr(a, "node_address", None)))
                if missing:
                    msg = (f"dials '{addr}', which is not in the listener certificate of node(s) {','.join(missing)}: "
                           + ("the Windows installer does not check; the agent would upgrade and then refuse the manager"
                              if platform == "windows" else
                              "macOS aborts" if platform == "darwin" else
                              "the Linux installer aborts and the agent stays on 4.x (upgrade_result 2)"))
                    if a.allow_cert_mismatch:
                        e["warn"].append(msg + " [requested anyway: --allow-cert-mismatch]")
                    else:
                        e["skip"] = msg
            if len(e["dialed"]) > 1 and not e["skip"]:
                # (a5) a 5.0 agent keeps only the last <server> address and never fails over (rpm and deb: AG1, F3;
                # Windows: this arm). The installers check that this last address answers before they install,
                # so an unreachable one aborts the upgrade (error 2, agent stays 4.x); a reachable one is a single point
                # of failure afterwards. The decision of which address to keep belongs to the user (conf-plan).
                e["warn"].append(f"dials {len(e['dialed'])} manager addresses on 4.x ({', '.join(e['dialed'])}): after the upgrade it dials only "
                                 f"'{e['dialed'][-1]}' and never fails over; the upgrade aborts (error 2) if that address does not answer "
                                 "on the HTTPS port from the host. Choose one address that reaches every node (conf-plan)")
            if fx.get("protocol") and "udp" in fx["protocol"]:
                e["warn"].append("legacy session over UDP: remoted's upgrade poller only walks agents with a TCP socket (legacy_task_delivery.c); expect the task to expire")
            um = fx.get("upgrade_module") or {}
            if um.get("enabled") == "no":
                e["skip"] = "the agent's own <agent-upgrade><enabled> is no"
            if platform not in ("windows", "darwin") and fx and fx.get("openssl") is None:
                e["no_openssl"] = True
                e["warn"].append("no openssl package in the 4.x inventory: the delivered CA cannot be validated; the agent would run 5.0 verifying nothing")
            if platform not in ("windows", "darwin") and fx and fx.get("curl") is None:
                e["warn"].append("no curl package in the 4.x inventory: the installer's manager check falls back to less strict checks")
            # mac1 (observed): with no anchor the macOS installer aborts (error 2) instead of upgrading unverified, because it
            # cannot tell from a package query that the installed agent is 4.x; Linux and Windows proceed unverified.
            if platform == "darwin" and ca_off and not e["skip"]:
                msg = (f"<legacy><ca_delivery> is off on node(s) {','.join(ca_off)}: the macOS installer aborts without a trust "
                       "anchor (it cannot tell a 4.x agent on macOS, so it does not proceed unverified as Linux and Windows do); "
                       "turn ca_delivery on, or place the manager CA at /Library/Ossec/etc/certs/root-ca.pem first")
                if getattr(a, "macos_anchor_placed", False):
                    e["warn"].append(msg + " [requested anyway: --macos-anchor-placed]")
                else:
                    e["skip"] = msg
        plan[aid] = e

    if legacy_off:
        need = [i for i, e in plan.items() if not e["skip"]]
        msg = f"node(s) {', '.join(legacy_off)}: <remote><legacy><enabled> is off"
        if need:
            problems.append(msg + f"; {len(need)} agent(s) below 5.0 cannot be upgraded (error 1828)")
        else:
            notes.append(msg + "; no agent on record needs the legacy channel")
    # waves: step-1 for old agents first, then one canary per operating system, then batches
    eligible = [i for i, e in plan.items() if not e["skip"]]
    canaries, seen = [], set()
    for i in sorted(eligible, key=lambda i: (plan[i]["status"] != "active", len(plan[i]["steps"]) > 1, i)):
        key = plan[i]["platform"] if a.canary_key == "platform" else f"{plan[i]['platform']}-{plan[i]['arch']}"
        if key not in seen:
            seen.add(key)
            canaries.append(i)
    rest = [i for i in sorted(eligible) if i not in canaries]
    for i in canaries:
        plan[i]["wave"] = 0
    for n, i in enumerate(rest):
        plan[i]["wave"] = 1 + n // a.batch_size
    return {"target": target, "manager": mf, "poll_interval": poll, "task_ttl": ttl, "repo5": repo5, "repo4": repo4,
            "problems": problems, "warnings": warnings, "notes": notes, "plan": plan, "dialed": dialed_all,
            "sans": sans_by_node}


def print_preflight(p):
    m = p["manager"]
    print(f"\nManager {m['hostname']} {m['version']} ({m.get('revision')}), target {p['target']}")
    for name, n in m["nodes"].items():
        leg = n["remote"].get("legacy", {})
        print(f"  node {name}: legacy {'on' if leg.get('enabled') else 'OFF'} port {leg.get('port')}/{','.join(leg.get('protocol', []))}, "
              f"https port {n['remote'].get('https', {}).get('port')}, ca_delivery {leg.get('ca_delivery')}, "
              f"poll {n.get('poll_interval')}s, task_ttl {n.get('task_manager', {}).get('task_ttl')}s, "
              f"legacy TCP sessions now {n.get('legacy_tcp_sessions')}")
        print(f"    listener certificate names: {', '.join(p['sans'].get(name, [])) or '(unknown)'}")
    print(f"  upgrade packages: {p['target']} from {p['repo5']}; 4.14.x step from {p['repo4']}")
    print(f"  addresses the fleet dials (4.x facts): " + (", ".join(f"{k} ({len(v)} agent(s))" for k, v in sorted(p['dialed'].items())) or "unknown"))
    for k, label in (("problems", "BLOCKER"), ("warnings", "warning"), ("notes", "note")):
        for x in p[k]:
            print(f"  {label}: {x}")
    print("\nAgents")
    for i, e in sorted(p["plan"].items()):
        path = " -> ".join([str(e["version"])] + [s["version"] for s in e["steps"]]) if e["steps"] else str(e["version"])
        where = f"wave {e['wave']}" + (" (canary)" if e.get("wave") == 0 else "") if "wave" in e else f"SKIP: {e['skip']}"
        print(f"  {i} {e['name']:<22} {e['platform']:<8} {e['arch']:<7} {e['status']:<15} {path:<32} {where}")
        for w in e["warn"]:
            print(f"        warning: {w}")
    waves = {}
    for i, e in p["plan"].items():
        if "wave" in e:
            waves.setdefault(e["wave"], []).append(i)
    print("\nPlan")
    for w in sorted(waves):
        print(f"  wave {w}{' (one canary per operating system)' if w == 0 else ''}: {', '.join(sorted(waves[w]))}")
    sk = [i for i, e in p["plan"].items() if e["skip"] and e["skip"] != "already-target"]
    print(f"  skipped: {', '.join(sorted(sk)) or 'none'}; already on target: "
          f"{', '.join(sorted(i for i, e in p['plan'].items() if e['skip'] == 'already-target')) or 'none'}")
    print(f"  time limits: delivery within poll interval {p['poll_interval']}s + sweep; a request is alive for task_ttl {p['task_ttl']}s\n")


# ---- state -------------------------------------------------------------------------------------
def load_state(path):
    if os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    return {"tool": TOOL_VERSION, "created": iso(now()), "agents": {}, "events": [], "waves": {}}


def save_state(path, st):
    """The state file is the memory that makes reruns safe (rule 16: a requested task is a commitment). E3 fold:
    synced before the rename and the directory after it, so a power cut leaves the old state or the new one."""
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(st, fh, indent=1, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def event(st, aid, what, detail=""):
    st["events"].append({"t": iso(now()), "agent": aid, "event": what, "detail": detail})
    log(f"[{aid}] {what}{': ' + detail if detail else ''}")


def merge_plan(st, p):
    """Bring a fresh preflight into the state without losing what was already done."""
    st.update(target=p["target"], poll_interval=p["poll_interval"], task_ttl=p["task_ttl"])
    for i, e in p["plan"].items():
        s = st["agents"].setdefault(i, {"state": "planned", "step": 0, "requests": [], "evidence": {}})
        done_steps = s.get("step", 0)
        s.update(name=e["name"], platform=e["platform"], arch=e["arch"], os=e["os"], dialed=e["dialed"], warn=e["warn"],
                 no_openssl=bool(e.get("no_openssl")))
        if s["state"] in TERMINAL_OK or s["state"] in OPEN:
            continue                       # finished or in flight: the new plan does not touch it
        if s["state"] == "upgraded-not-connecting":
            continue                       # cannot be reached over the legacy channel any more: manual
        if e["skip"] == "already-target":
            s["state"] = "already-target" if not s["requests"] else "upgraded"
            continue
        if e["skip"]:
            if s["state"] != "skipped" or s.get("reason") != e["skip"]:
                event(st, i, "skipped", e["skip"])
            s.update(state="skipped", reason=e["skip"])
            continue
        # steps still to do: preflight computes them from the version the agent reports now
        s["steps"], s["step"] = e["steps"], 0
        s["wave"] = e["wave"]
        if s["state"] in ("skipped", "planned", "held"):
            s["state"] = "planned"
            s.pop("reason", None)
        elif s["state"] in ("failed", "expired", "refused", "dropped"):
            s["state"] = "planned"         # eligible again; the request guard still applies
            s["retry_of"] = s.get("reason")
        _ = done_steps


# ---- requesting --------------------------------------------------------------------------------
def alive_until(st, r):
    """(a6) Until when a request can still lead to a push. A task that was never fetched turns 'expired' at the first
    cleanup pass after task_ttl. A task that was fetched and pushed without an answer is no longer in tasks.db as
    pending, but remoted keeps it in its retry list for RETRY_MAX_AGE from the first push and purges it only at the start
    of the first cycle after that; cycles are poll_interval apart from the END of the previous one, which can itself
    last most of an hour. Asking again before then can give a recovered agent two pushes."""
    first = first_push(r)
    if first:
        return first + RETRY_MAX_AGE + st["poll_interval"] + st.get("longest_cycle", st["task_ttl"])
    return r["t"] + st["task_ttl"] + st.get("cleanup_interval", CLEANUP_INTERVAL) + 60


def first_push(r):
    """(a6) The first push of a request that was pushed and never delivered (a state file from an older version keeps it
    as 'delivering'), or None."""
    if r.get("delivered"):
        return None
    return r.get("first_push") or r.get("delivering")


def thread_activity(api, st, a):
    """(a6) remoted's delivery-thread cycles over the last hours, from its push lines, whatever the agents' states: a gap of
    more than 300 s separates two cycles. Sets st['longest_cycle'] (bounds how late a retry-list purge can come) and
    st['thread_busy_until'] (the last push line: the thread is in a cycle while it is recent)."""
    since = now() - (st["poll_interval"] + RETRY_MAX_AGE + 2 * st["task_ttl"])
    times = []
    for node in st.get("nodes", ["node01"]):
        try:
            for aid, evs in index_logs(read_logs(api, node, since, a.manager_log)).items():
                times += [e["t"] for e in evs if e["kind"] in ("delivering", "delivered", "refused_stale")]
        except Exception as e:  # noqa: BLE001
            log(f"WARNING: log evidence unavailable from {node}: {e}")
    record_cycles(st, times)


def record_cycles(st, times):
    """ (merged: one implementation for verify and thread_activity, A6-D7's first leftover) remoted's cycles from its
    push lines: a gap of more than 300 s separates two cycles. The longest cycle bounds how late a retry-list purge can
    come; the last push says whether the delivery thread is busy right now."""
    times = sorted(times)
    if not times:
        return
    start = prev = times[0]
    for t in times[1:] + [None]:
        if t is None or t - prev > 300:
            st["longest_cycle"] = max(st.get("longest_cycle", 0), int(prev - start) + RESPONSE_TIMEOUT)
            if t is not None:
                start = t
        if t is not None:
            prev = t
    st["thread_busy_until"] = max(st.get("thread_busy_until", 0), times[-1])


def guard(st, aid, a, db_pending):
    """Why this agent must NOT be sent a request now, or None."""
    s = st["agents"][aid]
    for r in s["requests"]:
        if r.get("closed") and r["closed"] not in ("expired", "dropped"):
            continue
        until = alive_until(st, r)
        if now() < until:
            return (f"a request from {iso(r['t'])} for {r['version']} can still lead to a push until {iso(until)} "
                    f"({'retry list' if first_push(r) else 'task_ttl and the cleanup pass'})")
    if db_pending and aid in db_pending:
        return f"tasks.db holds {len(db_pending[aid])} pending remote_upgrade task(s) for this agent (not created by this state file)"
    return None


def request_upgrade(api, st, ids, version, repo, a):
    """One PUT /agents/upgrade for agents that share a target and repository."""
    params = {"agents_list": ",".join(ids), "upgrade_version": version, "wait_for_complete": "true"}
    if repo and not (repo.startswith("packages.wazuh.com/") and not a.always_name_repo):
        params["wpk_repo"] = repo
    if a.package_type:
        params["package_type"] = a.package_type
    t0 = now()
    if a.dry_run:
        log(f"DRY RUN: PUT /agents/upgrade {params}")
        return
    code, r = api.call("PUT", "/agents/upgrade", params, timeout=420)
    took = now() - t0
    data = r.get("data") or {}
    ok = set(data.get("affected_items") or [])
    st.setdefault("requests_log", []).append({"t": iso(t0), "agents": ids, "version": version, "repo": params.get("wpk_repo", "(manager default)"),
                                               "http": code, "seconds": round(took, 1), "message": r.get("message"),
                                               "failed_items": data.get("failed_items"), "detail": r.get("detail")})
    log(f"PUT /agents/upgrade {','.join(ids)} -> {version}: HTTP {code} in {took:.1f}s, {r.get('message') or r.get('detail') or r.get('title')}")
    failed = {}
    for f in data.get("failed_items") or []:
        for i in f.get("id", []):
            failed[i] = f"{f['error'].get('code')}: {f['error'].get('message')}"
    for i in ids:
        s = st["agents"][i]
        if i in ok:
            s["requests"].append({"t": t0, "version": version, "repo": params.get("wpk_repo", "(manager default)")})
            s.update(state="requested", reason=None)
            event(st, i, "requested", f"{version} (step {s['step'] + 1} of {len(s['steps'])})")
        elif code == 0:
            s["requests"].append({"t": t0, "version": version, "repo": params.get("wpk_repo", "(manager default)"), "uncertain": True})
            s.update(state="requested", reason="the connection dropped while the request was in flight; treated as sent")
            event(st, i, "requested (outcome unknown)", s["reason"])
        else:
            why = failed.get(i) or f"HTTP {code}: {r.get('detail') or r.get('message') or r.get('title')}"
            s.update(state="refused", reason=why)
            event(st, i, "refused by the manager", why)


# ---- verification ------------------------------------------------------------------------------
def verify(api, st, a, only=None):
    """Classify every agent with an open request from what the manager really has."""
    # agents that went silent after a delivery are looked at again on every pass: fixing the manager
    # certificate brings them back without any new request
    open_ids = [i for i, s in st["agents"].items()
                if (s["state"] in OPEN or s["state"] == "upgraded-not-connecting" or (INDEXER and s["state"] in TRUST_OPEN))
                and s["requests"] and (not only or i in only)]
    if not open_ids:
        return
    since = min(st["agents"][i]["requests"][-1]["t"] for i in open_ids) - 5
    logs = {}
    for node in st.get("nodes", ["node01"]):
        try:
            for aid, evs in index_logs(read_logs(api, node, since, a.manager_log)).items():
                logs.setdefault(aid, []).extend(evs)
        except Exception as e:  # noqa: BLE001
            log(f"WARNING: log evidence unavailable from {node}: {e}")
    # (a6) remoted's cycles as seen from its push lines (see record_cycles)
    record_cycles(st, [e["t"] for evs in logs.values() for e in evs if e["kind"] in ("delivering", "delivered", "refused_stale")])
    live = {x["id"]: x for x in fleet(api, open_ids)}
    # (a5) for each push, when the single delivery thread started the next agent's push: how long this one held it
    starts = sorted((e["t"], aid) for aid, evs in logs.items() if aid != "_manager" for e in evs if e["kind"] == "delivering")
    next_push = {}
    for aid, evs in logs.items():
        for e in evs:
            if e["kind"] == "delivering":
                later = [t for t, other in starts if other != aid and t >= e["t"]]
                next_push[(aid, e["t"])] = later[0] if later else None
    for i in open_ids:
        s, req = st["agents"][i], st["agents"][i]["requests"][-1]
        ag = live.get(i)
        if not ag:
            s.update(state="failed", reason="the agent is no longer in the manager's registry")
            req["closed"] = "agent removed"
            event(st, i, "failed", s["reason"])
            continue
        evs = sorted([e for e in logs.get(i, []) if e["t"] >= req["t"] - 2], key=lambda e: e["t"])
        kinds = {}
        for e in evs:
            kinds.setdefault(e["kind"], []).append(e)
        ev = s["evidence"]
        ev.update(version=ag.get("version"), status=ag.get("status"), lastKeepAlive=ag.get("lastKeepAlive"), checked=iso(now()))
        ka = parse_ts(ag.get("lastKeepAlive"))
        v, want = vtuple(ag.get("version")), vtuple(req["version"])
        # The API serves only the newest part of the log (spec: the last 2000 entries), so what was
        # seen once is kept in the state and merged with what the log shows now.
        seen = req.setdefault("seen", {})
        for k, lst in kinds.items():
            have = {json.dumps(x, sort_keys=True) for x in seen.get(k, [])}
            seen[k] = seen.get(k, []) + [x for x in lst if json.dumps(x, sort_keys=True) not in have]
        kinds = seen
        deliveries = kinds.get("delivered", [])
        if deliveries:
            req["delivered"] = deliveries[0]["t"]
            ev["delivered"] = iso(deliveries[0]["t"])
            ev["tasks_delivered"] = sorted({d["task"] for d in deliveries})
        if kinds.get("delivering"):
            req.setdefault("first_push", kinds["delivering"][0]["t"])
            req.setdefault("delivering", kinds["delivering"][0]["t"])
            if deliveries:
                # (ag1) the push that completed is the last attempt before the delivery line; an agent pushed from
                # remoted's retry list has earlier attempts, and counting from the first one (25 min for the hung
                # agents here) made the measured push time 70.8 s and the derived batch 16 instead of about 375
                req["delivering"] = max([d["t"] for d in kinds["delivering"] if d["t"] <= deliveries[0]["t"]] or [req["delivering"]])
        if len({d["task"] for d in kinds.get("delivering", [])}) > 1:
            ev["double_delivery"] = f"{len({d['task'] for d in kinds['delivering']})} different upgrade tasks were pushed to this agent for one request window"
        if kinds.get("ca_ok"):
            ev["ca"] = "delivered " + iso(kinds["ca_ok"][-1]["t"])
        elif kinds.get("ca_fail"):
            ev["ca"] = "NOT delivered: " + kinds["ca_fail"][-1]["detail"]
        results = kinds.get("result", [])
        if results:
            ev["agent_result"] = f"error {results[-1]['error']}: {results[-1]['message']} ({iso(results[-1]['t'])})"
        age = now() - req["t"]
        if s["state"] == "upgraded-not-connecting":
            if v and want and v >= want and ag.get("status") == "active" and ka > req["t"]:
                req["done"] = ka
                req["closed"] = "upgraded"
                req["closed_at"] = now()
                s.update(state="upgraded", reason=f"recovered without a new request: now reports {ag.get('version')}, active, last keepalive {ag.get('lastKeepAlive')}")
                event(st, i, "upgraded", s["reason"])
            continue
        if s["state"] in TRUST_OPEN:
            # (a5) the upgrade itself is done; only trust is open. Re-read the agent's own report: an endpoint fix
            # (token + wazuh-agent-auth --certs-only + restart) shows up here as a newer report with a verifying mode
            try:
                tls = INDEXER.tls_modes([i]).get(i)
            except Exception as e:  # noqa: BLE001
                ev["tls"] = f"indexer not readable: {e}"
                continue
            if tls and tls["reported"] >= req["t"] and tls["mode"] in ("full", "certificate", "system"):
                ev["tls"] = f"verification_mode={tls['mode']}, CA {tls['ca'] or 'none'}, dials {','.join(tls['dials']) or '?'} (agent's own report, wazuh-agent-config, {iso(tls['reported'])})"
                req["closed"] = "upgraded"
                req["closed_at"] = now()
                s.update(state="upgraded", reason=f"trust proven after the verdict '{s['state']}': the agent now reports verification_mode={tls['mode']} "
                                                  f"({iso(tls['reported'])}); no new request was sent")
                event(st, i, "upgraded", s["reason"])
            elif tls and tls["reported"] >= req["t"] and s["state"] == "upgraded-trust-unconfirmed" and tls["mode"] in (None, "none"):
                ev["tls"] = f"verification_mode={tls['mode']}, CA {tls['ca'] or 'none'} (agent's own report, {iso(tls['reported'])})"
                s.update(state="upgraded-not-verifying", reason=f"the agent's own report arrived late: verification_mode={tls['mode']}; it accepts any certificate")
                event(st, i, "upgraded-not-verifying", s["reason"])
            continue

        def close(state, reason=""):
            req["closed"] = state
            req["closed_at"] = now()
            s.update(state=state, reason=reason or None)
            event(st, i, state, reason)

        # 1. the agent reports the version that was asked for
        if v and want and v >= want:
            if ag.get("status") != "active" or ka < req["t"]:
                continue                                    # version recorded but not seen since: wait for a keepalive
            req["done"] = ka
            if s["step"] + 1 < len(s["steps"]):
                req["closed"] = "step-done"
                req["closed_at"] = now()
                s["step"] += 1
                s["state"] = "planned"
                event(st, i, "step done", f"reports {ag.get('version')}; next: {s['steps'][s['step']]['version']}")
                continue
            tls, idx_error = None, False
            if want >= (5, 0, 0) and INDEXER:
                try:
                    tls = INDEXER.tls_modes([i]).get(i)
                except Exception as e:  # noqa: BLE001
                    ev["tls"] = f"indexer not readable: {e}"
                    idx_error = True      # (ag1) an unreadable indexer must not hold the verdict until task_ttl
                # (ag1) the grace is counted from the first time the new version was seen, not from the last
                # keepalive: an active agent's keepalive is always recent, which kept A1's wait open for task_ttl
                first_seen = req.setdefault("target_seen", now())
                if not idx_error and (not tls or tls["reported"] < req["t"]) and now() - first_seen < a.config_report_grace:
                    del req["done"]
                    continue                                # the agent has not reported its 5.x configuration yet
            if tls and tls["reported"] >= req["t"]:
                ev["tls"] = f"verification_mode={tls['mode']}, CA {tls['ca'] or 'none'}, dials {','.join(tls['dials']) or '?'} (agent's own report, wazuh-agent-config)"
                if tls["mode"] in ("full", "certificate", "system"):
                    close("upgraded", f"reports {ag.get('version')}, active, last keepalive {ag.get('lastKeepAlive')}; the agent reports verification_mode={tls['mode']}")
                else:
                    close("upgraded-not-verifying", f"reports {ag.get('version')} and is active, but the agent reports verification_mode={tls['mode']}: "
                                                     f"it accepts any certificate. The manager log says the CA was {ev.get('ca', 'not delivered')}")
            elif want >= (5, 0, 0) and s.get("no_openssl"):
                close("upgraded-trust-unconfirmed", f"reports {ag.get('version')}, active; the manager logged the CA as {ev.get('ca', 'not delivered')}, but the 4.x "
                                                    "inventory had no openssl on this host, so the agent could not validate it and most likely verifies nothing")
            elif want >= (5, 0, 0) and not str(ev.get("ca", "")).startswith("delivered"):
                close("upgraded-trust-unconfirmed", f"reports {ag.get('version')}, active; manager CA: {ev.get('ca', 'no delivery line found in the log')}")
            elif want >= (5, 0, 0) and INDEXER:
                # (a5) with the indexer given, the manager's "delivered the manager CA" line is not evidence of trust
                # (A1 G10: it is written for agents that then verify nothing); without the agent's own report the
                # verdict stays open on trust and is re-read on every pass
                close("upgraded-trust-unconfirmed", f"reports {ag.get('version')}, active; no configuration report in wazuh-agent-config "
                                                    f"{int(now() - req['target_seen'])}s after the new version was seen"
                                                    + (" (indexer not readable)" if idx_error else "") + "; re-read on every pass")
            else:
                close("upgraded", f"reports {ag.get('version')}, active, last keepalive {ag.get('lastKeepAlive')}; CA {ev.get('ca', 'n/a for a 4.x step')}")
            continue
        # 2. explicit failure evidence
        bad = [r for r in results if r["error"] != 0]
        if bad:
            close("failed", f"the agent reported upgrade result error {bad[-1]['error']}: {bad[-1]['message']}; still on {ag.get('version')}")
            continue
        if kinds.get("installer_failed"):
            close("failed", f"installer script failed on the agent (exit status {kinds['installer_failed'][-1]['detail']}); still on {ag.get('version')}")
            continue
        if kinds.get("push_failed") and not deliveries:
            last = kinds["push_failed"][-1]
            if now() - last["t"] > a.push_retry_grace:
                close("failed", f"the manager could not push the package: {last['detail']}")
            else:
                s["state"] = "delivering"
            continue
        # 3. delivered, no result yet
        if deliveries:
            t_d = deliveries[0]["t"]
            if now() - t_d < a.install_grace:
                if s["state"] != "installing":
                    event(st, i, "delivered", f"package pushed at {iso(t_d)}; waiting for the agent to report {req['version']}")
                s["state"] = "installing"
                continue
            if ka > t_d + a.restart_window and ag.get("status") == "active":
                close("failed", f"package delivered at {iso(t_d)} but the agent keeps reporting {ag.get('version')} on the legacy channel "
                                f"(last keepalive {ag.get('lastKeepAlive')}) and reported no result")
            else:
                close("upgraded-not-connecting",
                      f"package delivered at {iso(t_d)}, no failure reported, and the agent has been silent since "
                      f"{ag.get('lastKeepAlive')} (status {ag.get('status')}): it most likely runs {req['version']} and cannot reach or does not trust "
                      f"the manager on the HTTPS port. The manager cannot tell this from a dead host")
            continue
        # 4. not delivered
        if kinds.get("retry_dropped"):
            close("dropped", f"pushed at {iso(kinds['delivering'][0]['t']) if kinds.get('delivering') else '?'}, the agent never answered, and remoted "
                             f"dropped the task from its full retry list at {iso(kinds['retry_dropped'][-1]['t'])}: the task is lost "
                             "(tasks.db still says 'delivered'); a new request is safe")
            req["closed"] = "dropped"
            continue
        if kinds.get("delivering"):
            # merged A5 x A6: A6's retry-list clock decides when an unanswered push is gone for good ('dropped', replacing
            # A5's age-based 'expired'); A5's evidence decides what an open push is (slow link, host gone, frozen agent),
            # and A6's immediate refusal line marks an agent silent past agents_disconnection_time.
            # (a6) the task left tasks.db at its first push; what can still push it is remoted's retry list, which keeps it
            # RETRY_MAX_AGE from the first push and drops it at the next cycle start with a DEBUG line only
            fp, last_push = kinds["delivering"][0]["t"], kinds["delivering"][-1]["t"]
            req["first_push"] = fp
            refused = [x for x in kinds.get("refused_stale", []) if 0 <= x["t"] - last_push <= 5]
            until = alive_until(st, req)
            if now() >= until:
                close("dropped", f"pushed {len(kinds['delivering'])} time(s) from {iso(fp)} to {iso(last_push)} and never answered; remoted "
                                 f"keeps such a task {RETRY_MAX_AGE}s from the first push and then drops it, logged at DEBUG only; tasks.db "
                                 "says 'delivered'. A new request is safe now")
                continue
            # (a5) remoted pushes one agent at a time and logs only 'delivering' before a push that gets no answer, so
            # 0.6 called every push older than 120 s 'no-answer'. Observed here, three different things look like that:
            #  - a slow link: the push is still running (227 s at 200 ms RTT) and the agent keeps sending keepalives;
            #  - a frozen agent (session open, process not answering): the thread waits response_timeout (60 s) and
            #    the next agent's 'delivering' line comes 60 s later; it costs that again at every poll;
            #  - a host powered off, paused or cut off: remoted's TCP keepalive closes its session in 50 to 70 s, the
            #    push then ends in the same second and costs the thread nothing; the API still says 'active'.
            nxt = next_push.get((i, last_push))
            gap = None if nxt is None else nxt - last_push
            ka_fresh = ka > last_push + 1
            # (a5) observed: a frozen agent held the thread 60 s on its first attempt only; remoted's retry 22 min later
            # ended in the same second (no byte was written to its still-open session). Any attempt that held the thread
            # means the session was open: that agent is 'no-answer', never 'host-gone'
            held = [next_push.get((i, d["t"])) - d["t"] for d in kinds["delivering"] if next_push.get((i, d["t"])) is not None]
            if held and max(held) >= RESPONSE_TIMEOUT - 5 and not ka_fresh:
                gap = max(held)
            if gap is None and ka_fresh and now() - last_push < a.slow_push_limit:
                ev["push"] = (f"push started {iso(last_push)}, {int(now() - last_push)}s ago and not finished; the agent still sends keepalives "
                              f"(last {ag.get('lastKeepAlive')}), so the package is still on its way (slow link)")
                s["state"] = "delivering"
                continue
            if refused:
                req["stale_refusal"] = True
                if s["state"] != "no-answer-stale":
                    event(st, i, "no-answer-stale", f"push at {iso(last_push)} refused at once by remoted ('cannot send request to agent'): the agent "
                                                    "has sent nothing for longer than agents_disconnection_time, so the attempt cost the delivery "
                                                    f"thread nothing; retried at every cycle until about {iso(fp + RETRY_MAX_AGE)}")
                s["state"] = "no-answer-stale"
                continue
            if gap is not None and gap <= 5 and not ka_fresh:
                if s["state"] != "host-gone":
                    event(st, i, "host-gone", f"the push at {iso(last_push)} ended at once with no answer and the agent has sent no keepalive since "
                                              f"{ag.get('lastKeepAlive')} (the API still says '{ag.get('status')}'): its legacy session was already "
                                              "closed, as remoted's TCP keepalive does for a host that is powered off, paused or cut off. It costs "
                                              f"the delivery thread nothing; remoted keeps the task in its retry list until about {iso(fp + RETRY_MAX_AGE)}")
                s["state"] = "host-gone"
                continue
            if (gap is not None and gap >= RESPONSE_TIMEOUT - 5) or now() - last_push > RESPONSE_TIMEOUT * 2:
                if s["state"] != "no-answer":
                    event(st, i, "no-answer", f"push started {iso(last_push)} ({len(kinds['delivering'])} attempt(s)); the session is open but the agent "
                                              f"never answered (no keepalive since {ag.get('lastKeepAlive')}): each attempt costs the delivery thread "
                                              f"{RESPONSE_TIMEOUT}s, and remoted retries it at the start of every cycle until about {iso(fp + RETRY_MAX_AGE)}, "
                                              "silently at INFO")
                s["state"] = "no-answer"
                continue
            s["state"] = "delivering"
            continue
        expire_at = alive_until(st, req)
        if now() > expire_at:
            busy = st.get("thread_busy_until", 0) >= req["t"] + st["task_ttl"]
            close("expired", f"no push in {int(age)}s: the task expired at the cleanup pass after task_ttl ({st['task_ttl']}s); agent status "
                             f"{ag.get('status')}" + ("; the delivery thread was still busy with earlier agents when it expired: the batch "
                                                      "was too large for the time left" if busy and ag.get('status') == 'active' else ""))
            continue
        if ag.get("status") != "active":
            if s["state"] != "waiting-for-agent":
                event(st, i, "waiting-for-agent", f"agent is {ag.get('status')}; the task is offered only while it is connected and expires at {iso(req['t'] + st['task_ttl'])}")
            s["state"] = "waiting-for-agent"
        elif age > st["poll_interval"] + a.sweep_allowance and s["state"] != "delivering":
            ev["late"] = f"no delivery line {int(age)}s after the request although the agent is active (poll interval {st['poll_interval']}s)"
            s["state"] = "requested"
        else:
            s["state"] = "requested"


# ---- run ---------------------------------------------------------------------------------------
def run(api, a, facts_4x):
    lock = open(a.state + ".lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit(f"another fleet-upgrade run holds {a.state}.lock")
    st = load_state(a.state)
    p = preflight(api, a, facts_4x)
    print_preflight(p)
    if p["problems"] and not a.ignore_blockers:
        sys.exit("preflight found blockers; nothing was requested")
    st["nodes"] = list(p["manager"]["nodes"])
    verify(api, st, a)                       # settle what earlier runs left open before planning
    merge_plan(st, p)
    save_state(a.state, st)
    t_start, deadline = now(), now() + a.max_wait
    agents = st["agents"]

    def in_play():
        return {i: s for i, s in agents.items() if "wave" in s and s["state"] not in ("skipped", "already-target")}

    def is_canary(i):
        """(a5) a wave-0 agent is a canary only if no agent of its operating system had already upgraded with trust
        proven when it was requested. A re-run re-elects wave 0 among the agents left; without this, the re-run's first
        agent was neither counted by the brake nor held its lane's batch open, although the gate let it go"""
        s = agents[i]
        if s.get("wave") != 0:
            return False
        t0 = min((r["t"] for r in s["requests"]), default=now())
        return not any(c != i and cs.get("platform") == s.get("platform") and cs["state"] == "upgraded"
                       and any(r.get("done") and r["done"] < t0 for r in cs.get("requests", [])) for c, cs in agents.items())

    def gate(i):
        """go / wait / hold: an agent outside the canary wave moves only after the canary of its own
        operating system succeeded. Operating systems do not wait for each other."""
        s = agents[i]
        if is_canary(i) or a.no_canary_gate:
            return "go", ""
        # (ag1) a re-run re-elects canaries among the agents not yet upgraded; an operating system that already has
        # a verified upgrade (from this run or an earlier one) does not wait for a new canary
        if any(cs.get("platform") == s["platform"] and cs["state"] == "upgraded" and cs.get("requests") for cs in agents.values()):
            return "go", ""
        cans = [c for c, cs in agents.items() if cs.get("wave") == 0 and cs.get("platform") == s["platform"] and c != i]
        if not cans:
            return "go", ""
        # (a5) a canary releases its lane only with trust proven (or when it was already on the target): a canary that
        # upgraded but verifies nothing, or whose trust is unconfirmed, holds the lane like a failed one; A1-0.6 let
        # every TERMINAL_OK state through, so one unverifying canary sent its whole operating system the same way
        if all(agents[c]["state"] in VERIFIED_OK for c in cans):
            return "go", ""
        badc = [c for c in cans if agents[c]["state"] in TERMINAL_BAD or agents[c]["state"] in TRUST_OPEN
                or agents[c]["state"] in ("skipped", "held")]
        if badc:
            return "hold", f"canary {badc[0]} for {s['platform']} is '{agents[badc[0]]['state']}'"
        return "wait", ""

    while True:
        play = in_play()
        closed = [s for i_, s in play.items() if not is_canary(i_) and (s["state"] in TERMINAL_OK or s["state"] in TERMINAL_BAD)]
        # (a5) an agent proven to verify nothing is a failure for the brake, as it is for the canary gate
        bad = [s for s in closed if s["state"] in TERMINAL_BAD or s["state"] in TRUST_BAD]
        brake = len(closed) >= a.min_sample and len(bad) / len(closed) > a.max_failure_ratio
        if brake and not st.get("brake"):
            st["brake"] = f"{len(bad)} of {len(closed)} agents outside the canary wave failed (limit {a.max_failure_ratio:.0%}); no new requests"
            log("STOP: " + st["brake"])
        elif not brake and st.get("brake"):
            st.setdefault("brake_history", []).append({"t": iso(now()), "was": st.pop("brake"), "released": f"{len(bad)} of {len(closed)} now"})
        # (a5) a held agent is gated again on every pass: its canary may have been fixed in the meantime
        for i, s in agents.items():
            if s["state"] == "held" and "wave" in s and gate(i)[0] == "go":
                s.update(state="planned", reason=None)
                event(st, i, "released", "its canary is now verified")
        thread_activity(api, st, a)          # (a6) whatever the agents' states, from remoted's own push lines
        # batch size from what was measured: remoted pushes one agent at a time, and a task that is
        # not reached within task_ttl of its creation expires without a trace
        pushes = sorted(r["delivered"] - r["delivering"] for s in agents.values() for r in s["requests"]
                        if r.get("delivered") and r.get("delivering"))
        if pushes:
            # (a6) the formula measured in arm A6. A task must be fetched by the sweep within task_ttl of its creation. A new
            # batch is asked for only while the delivery thread is idle, so it waits at most one poll for the next cycle;
            # that cycle first re-pushes the retry list (response_timeout for each agent that keeps its session and does
            # not answer; nothing for one silent longer than agents_disconnection_time, which remoted refuses at once), and
            # then walks the agents in key order, response_timeout for each silent one, the measured push for the others.
            h = max(1.0, pushes[len(pushes) // 2])
            st["measured_push_seconds"] = round(h, 1)
            pushed = [s_ for s_ in agents.values() if any(r.get("first_push") or r.get("delivering") for r in s_["requests"])]
            # pushed and never delivered, and not refused at once as silent > agents_disconnection_time
            fresh_silent = [s_ for s_ in agents.values() if s_["state"] != "no-answer-stale"
                            and any(first_push(r) and not r.get("stale_refusal") for r in s_["requests"])]
            sigma = max(FRESH_SILENT_PRIOR, len(fresh_silent) / len(pushed)) if pushed else FRESH_SILENT_PRIOR
            # the next cycle starts poll_interval after the end of the current one (the last push line plus at most one
            # response_timeout), or poll_interval from now if the thread has been idle longer than that
            next_cycle = max(now(), st.get("thread_busy_until", 0) + RESPONSE_TIMEOUT) + st["poll_interval"]
            # only entries still in the list at the next cycle, for agents that will still have a fresh session then
            # (an agent silent longer than agents_disconnection_time is refused at once and costs nothing)
            in_retry = [s_ for s_ in fresh_silent
                        if any(first_push(r) and first_push(r) + RETRY_MAX_AGE >= next_cycle for r in s_["requests"])
                        and parse_ts(s_.get("evidence", {}).get("lastKeepAlive")) + DISCONNECTION_TIME >= next_cycle]
            retry_cost = RESPONSE_TIMEOUT * min(RETRY_LIST_MAX, len(in_retry))
            budget = st["task_ttl"] - st["poll_interval"] - retry_cost - a.sweep_allowance
            per = h * (1 - sigma) + RESPONSE_TIMEOUT * sigma
            st["safe_batch"] = max(0, min(int(budget / (per * a.batch_safety)), UPGRADE_MAX_AGENTS))
            st["batch_formula"] = {"push_s": round(h, 1), "fresh_silent_share": round(sigma, 3), "retry_list_s": retry_cost,
                                   "budget_s": budget, "per_agent_s": round(per, 1), "safety": a.batch_safety, "safe_batch": st["safe_batch"]}
            st["silent_agents"] = len(fresh_silent)
        db_pending = pending_tasks_from_db(a.tasks_db) if a.tasks_db else None
        todo = []
        for i in sorted(play, key=lambda i: (agents[i]["wave"], i)):
            s = agents[i]
            if s["state"] != "planned":
                continue
            g, why = gate(i)
            if g == "hold":
                s.update(state="held", reason=why)
                event(st, i, "held", why)
                continue
            if g == "wait" or brake:
                continue
            why = guard(st, i, a, db_pending)
            if why:
                if s.get("guard") != why:
                    event(st, i, "not requested", why)
                s["guard"] = why
                continue
            s.pop("guard", None)
            todo.append(i)
        if todo and not a.dry_run:
            # somebody else may have upgraded it in the meantime: never ask for a version it already runs
            for x in fleet(api, todo):
                s = agents[x["id"]]
                step = s["steps"][s["step"]]
                if (vtuple(x.get("version")) or (0,)) >= vtuple(step["version"]):
                    todo.remove(x["id"])
                    if s["step"] + 1 < len(s["steps"]):
                        s["step"] += 1
                    else:
                        s.update(state="upgraded" if s["requests"] else "already-target",
                                 reason=f"found reporting {x.get('version')} before this run asked for it")
                        event(st, x["id"], s["state"], s["reason"])
        # (a5) batch boundary per operating system lane. A1-0.6 refilled a sliding window of 'requested/delivering'
        # agents, so the next batch went out as soon as the previous one was pushed (agents 'installing'), before
        # any verdict, and the brake could only stop requests after tasks that cannot be cancelled already existed.
        # Now a lane's next batch is requested only when no agent of its previous one is still open (LANE_BUSY);
        # canaries keep their own gate. (merged) The size of a batch is A6's time-based safe batch (rule 23).
        limit = min(a.batch_size, st.get("safe_batch", UPGRADE_MAX_AGENTS), UPGRADE_MAX_AGENTS)
        busy = {}
        for i_, s in play.items():
            if s["state"] in LANE_BUSY and not is_canary(i_):
                busy[s.get("platform")] = busy.get(s.get("platform"), 0) + 1
        chosen, per_lane = [], {}
        # (a6) never ask while remoted's delivery thread is in a cycle: an agent it has already passed would wait for the
        # rest of this cycle, a whole poll and the next cycle's retry list, which is how batch B expired in A6 (rule 23)
        thread_busy = now() - st.get("thread_busy_until", 0) < RESPONSE_TIMEOUT + 60
        if thread_busy and todo:
            if not st.get("busy_note"):     # its own key; sharing room_note with A5's lane note printed it every pass
                st["busy_note"] = True
                log(f"{len(todo)} agents ready; not asking while remoted's delivery thread is in a cycle (last push {iso(st['thread_busy_until'])})")
        else:
            st.pop("busy_note", None)
            for i in todo:
                lane = agents[i].get("platform")
                if not is_canary(i) and busy.get(lane):
                    continue
                if per_lane.get(lane, 0) >= limit:
                    continue
                per_lane[lane] = per_lane.get(lane, 0) + 1
                chosen.append(i)
        waiting = [i for i in todo if i not in chosen]
        room = len(chosen)
        groups = {}
        for i in chosen:
            step = agents[i]["steps"][agents[i]["step"]]
            groups.setdefault((step["version"], step["repo"]), []).append(i)
        if waiting and not thread_busy and st.get("room_note") != [len(todo), room, sorted(busy.items())]:
            st["room_note"] = [len(todo), room, sorted(busy.items())]
            log(f"{len(todo)} agents are ready, {room} are requested now: at most {limit} per operating system and batch "
                f"(push {st.get('measured_push_seconds', '?')}s per agent, task_ttl {st['task_ttl']}s); lanes still open: "
                + (", ".join(f"{k} {v} agent(s)" for k, v in sorted(busy.items())) or "none"))
        for (version, repo), g in groups.items():
            request_upgrade(api, st, g, version, repo, a)
        save_state(a.state, st)
        if a.dry_run:
            break
        verify(api, st, a)
        save_state(a.state, st)
        play = in_play()
        open_left = [i for i, s in play.items() if s["state"] in OPEN]
        can_move = [i for i, s in play.items() if s["state"] == "planned" and not s.get("guard") and not brake and gate(i)[0] in ("go", "hold")]
        if not open_left and not can_move:
            break
        # E7-aio U9: an agent stopped after its request held the run silently until its task expired (task_ttl and the
        # cleanup pass, 66 minutes) and then failed the gate. When every open agent is only waiting for its host to
        # connect, the run stops after --leave-disconnected seconds: the request stays with the manager until it
        # expires, the agent is named, and a re-run continues (or asks again once it has expired)
        parked = [i for i in open_left if play[i]["state"] == "waiting-for-agent"]
        if open_left and len(parked) == len(open_left) and not can_move:
            st.setdefault("parked_since", now())
            if now() - st["parked_since"] >= a.leave_disconnected:
                log("stopping: agent(s) %s not connected, their upgrade requested and kept by the manager until it expires; "
                    "they stay on 4.x until they connect: re-run then" % ", ".join("%s (%s)" % (i, play[i].get("name", "")) for i in parked))
                st.pop("parked_since", None)
                break
        else:
            st.pop("parked_since", None)
        if now() - st.get("progress_at", t_start) >= 60 and open_left:      # never silent for more than a minute
            st["progress_at"] = now()

            log(progress_line(play, open_left, st, a.leave_disconnected, getattr(a, "sweep_allowance", 0), now()))
        if a.once or now() > deadline:
            log(f"stopping with open agents {', '.join(open_left) or '-'} ({'--once' if a.once else 'max wait reached'}); re-run to continue")
            break
        time.sleep(a.check_every)
    # per-wave times, from the requests themselves
    st["waves"] = {}
    for i, s in agents.items():
        if "wave" not in s or not s["requests"]:
            continue
        w = st["waves"].setdefault(str(s["wave"]), {"agents": {}, "first_request": None, "last_outcome": None})
        w["agents"][i] = s["state"]
        t0 = min(r["t"] for r in s["requests"])
        t1 = max((r.get("closed_at") or 0) for r in s["requests"])
        w["first_request"] = min(w["first_request"] or t0, t0)
        w["last_outcome"] = max(w["last_outcome"] or 0, t1) if all(x in TERMINAL_OK or x in TERMINAL_BAD for x in w["agents"].values()) else None
    st["last_run_seconds"] = round(now() - t_start)
    save_state(a.state, st)
    report(st, a)


# ---- report ------------------------------------------------------------------------------------
ACTIONS = {
    "upgraded": "none",
    "already-target": "none",
    "upgraded-trust-unconfirmed": "confirm on the host that etc/certs/root-ca.pem exists and ossec.log has no 'TLS verification is DISABLED'; if not, install the anchor with an enrollment token (wazuh-agent-auth --certs-only)",
    "upgraded-not-verifying": "on the host: stop the agent, run wazuh-agent-auth --token-file <token> --certs-only (token: wazuh-manager-authd --create-enrollment-token --address <address the agent dials> --no-credential), start it; nothing the manager sends can install the anchor now",
    "upgraded-not-connecting": "go to the host: check the agent log for a certificate error against the address it dials; fix the listener certificate or install the anchor; a re-request cannot reach it",
    "failed": "read the reason; fix it and re-run (the agent is still on 4.x and still reporting)",
    "expired": "the agent never took the task; re-run when it is connected",
    "refused": "the manager refused the request; fix the cause and re-run",
    "held": "its canary did not succeed or its trust is not proven; fix the canary first (for trust: the endpoint fix, or --indexer), then re-run",
    "skipped": "not attempted; see the reason",
    "planned": "not requested yet; re-run",
    "requested": "open: waiting for remoted's next poll", "delivering": "open: package being pushed",
    "no-answer": "open: pushed, the agent keeps its session but never answered (agent or its upgrade module hung); each cycle re-spends response_timeout on it for 1 h from the first push; check the host",
    "host-gone": "open: the host is off, paused or cut off (session closed by TCP keepalive); bring it back within 1 h of the push and remoted delivers the task, else re-run",
    "no-answer-stale": "open: the agent has sent nothing for longer than agents_disconnection_time; remoted refuses to push to it (costs nothing) and keeps the task 1 h; check the host",
    "dropped": "remoted dropped the task (retry list full, or 1 h after the first push without an answer); tasks.db still says 'delivered'; fix the host and re-run (a new request is safe)",
    "installing": "open: delivered, waiting for the agent to come back", "waiting-for-agent": "open: agent not connected",
}


def report(st, a):
    print("\n=== fleet upgrade report " + iso(now()) + f" (target {st.get('target')}) ===")
    counts = {}
    for s in st["agents"].values():
        counts[s["state"]] = counts.get(s["state"], 0) + 1
    print("totals: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    byos = {}
    for s in st["agents"].values():
        if s["requests"]:
            o = byos.setdefault(s.get("platform", "?"), [0, 0])
            o[1] += 1
            o[0] += s["state"] in TERMINAL_OK
    if byos:
        print("requested agents that ended upgraded, per operating system: " + ", ".join(f"{k} {v[0]}/{v[1]}" for k, v in sorted(byos.items())))
    for w, d in sorted(st.get("waves", {}).items()):
        if "first_request" not in d:
            continue
        dur = f"{int(d['last_outcome'] - d['first_request'])}s from first request to last outcome" if d.get("last_outcome") else "still open"
        print(f"wave {w}: first request {iso(d['first_request'])}, {dur}; " + ", ".join(f"{i}={x}" for i, x in sorted(d["agents"].items())))
    if st.get("measured_push_seconds"):
        print(f"measured push time per agent: {st['measured_push_seconds']}s; batch limit derived from it: {st.get('safe_batch')}")
    if st.get("brake"):
        print("STOPPED: " + st["brake"])
    print()
    for i, s in sorted(st["agents"].items()):
        ev = s.get("evidence", {})
        print(f"{i} {s.get('name', ''):<22} {s.get('platform', ''):<8} {s['state']}")
        if s.get("reason"):
            print(f"     reason:   {s['reason']}")
        for r in s["requests"]:
            line = f"     request:  {iso(r['t'])} -> {r['version']}"
            if r.get("delivered"):
                line += f", delivered +{int(r['delivered'] - r['t'])}s"
                if r.get("delivering"):
                    line += f" (push took {int(r['delivered'] - r['delivering'])}s)"
            if r.get("done"):
                line += f", target version seen +{int(r['done'] - r['t'])}s"
            print(line + (f" [{r.get('closed')}]" if r.get("closed") else " [open]"))
        if ev:
            print("     evidence: " + "; ".join(f"{k}={v}" for k, v in sorted(ev.items()) if k != "checked"))
        for w in s.get("warn", []):
            print(f"     warning:  {w}")
        print(f"     action:   {ACTIONS.get(s['state'], '?')}")
    if a.report:
        with open(a.report, "w") as fh:
            json.dump({"generated": iso(now()), "totals": counts, "agents": st["agents"], "waves": st.get("waves")}, fh, indent=1, sort_keys=True)
        print(f"\nJSON report written to {a.report}")


def legacy_status(api):
    """When can the legacy ports be closed: no agent below 5.0 on record, no legacy session open."""
    old = [x for x in fleet(api) if (vtuple(x.get("version")) or (0,)) < (5, 0, 0)]
    mf = manager_facts(api)
    sess = {n: d.get("legacy_tcp_sessions") for n, d in mf["nodes"].items()}
    print(f"agents not on 5.x in the registry: {len(old)}" + (": " + ", ".join(f"{x['id']} ({x.get('version')}, {x.get('status')})" for x in old) if old else ""))
    print("legacy TCP sessions per node: " + ", ".join(f"{n}={v}" for n, v in sess.items()))
    safe = not old and all(v == 0 for v in sess.values())
    print("legacy channel can be closed: " + ("YES (no pre-5.0 agent on record and no legacy session)" if safe else
          "NO" + (" - agents below 5.0 remain on record (a disconnected one will dial 1514 when it returns)" if old else " - sessions are still open")))


def trust_audit(api, node_addresses=None):
    """Every 5.x agent and the TLS verification it reports for itself."""
    if not INDEXER:
        sys.exit("trust-audit needs --indexer: the manager API does not expose what an agent verifies")
    modes = INDEXER.tls_modes()
    nodes = manager_facts(api)["nodes"]
    sans = {n: d.get("tls", {}).get("listener", {}).get("sans", []) for n, d in nodes.items()}
    bad = 0
    for x in fleet(api):
        v = vtuple(x.get("version")) or (0,)
        m = modes.get(x["id"])
        if v < (5, 0, 0):
            verdict = "4.x agent: verifies nothing by design (legacy channel)"
        elif not m:
            verdict = "NO configuration report in wazuh-agent-config: unknown"
        else:
            miss = [d for d in m["dials"] if cert_missing(d, sans, nodes, node_addresses)]   # per node
            verdict = f"verification_mode={m['mode']}, CA {m['ca'] or 'none'}, dials {','.join(m['dials']) or '?'}"
            if m["mode"] in (None, "none"):
                verdict += "  <-- VERIFIES NOTHING"
                bad += 1
            if miss:
                verdict += f"  <-- dials {','.join(miss)}, not in the listener certificate"
        print(f"{x['id']} {x['name']:<22} {str(x.get('version')):<9} {x.get('status'):<13} {verdict}")
    print(f"{bad} agent(s) on 5.x accept any manager certificate")


# ---- (ag1) the agents' own ossec.conf ----------------------------------------------------------------
IGNORED_CLIENT = {"notify_time": "keepalive interval (5.0 default 10 s)", "auto_restart": "restart on pushed configuration (5.0 default yes)",
                  "config-profile": "profile the agent matches <agent_config profile=...> blocks with",
                  "time-reconnect": "deprecated, no effect", "crypto_method": "deprecated, no effect",
                  "ip_update_interval": "deprecated, no effect", "force_reconnect_interval": "deprecated, no effect"}


def conf_plan(api, facts_4x, agents=None):
    """What a 5.0 agent will do with its 4.x <client> block, from the facts captured on 4.x, and which
    profile-targeted group blocks stop applying when the upgrade drops <config-profile>."""
    if not facts_4x:
        sys.exit("conf-plan needs --fleet-facts: the agents' <client> blocks can only be read from the 4.x manager")
    groups = {}
    for g in api.items("/groups"):
        c, r = api.call("GET", f"/groups/{g['name']}/files/agent.conf")
        blocks = (r.get("data") or {}).get("affected_items", []) if c == 200 else []
        groups[g["name"]] = sorted({p.strip() for b in blocks for p in str((b.get("filters") or {}).get("profile", "")).split("|") if p.strip()})
    totals = {"agents": 0, "multi_address": 0, "profile_blocks_lost": 0, "changed_settings": 0}
    for aid, f in sorted(facts_4x.items()):
        if agents and aid not in agents:
            continue
        cl = f.get("client") or {}
        if not cl:
            print(f"{aid} {f.get('name')}: no <client> captured on 4.x ({'; '.join(f.get('notes', []))}): plan unknown")
            continue
        totals["agents"] += 1
        servers = [x.get("address") for x in cl.get("server", []) if x.get("address")]
        lines = []
        if len(servers) > 1:
            totals["multi_address"] += 1
            lines.append(f"dials {', '.join(servers)} on 4.x; 5.0 keeps only '{servers[-1]}' and never fails over: DECISION NEEDED (one address for every node)")
        prof = [x.strip() for x in str(cl.get("config-profile", "")).split(",") if x.strip()]
        lost = sorted({f"{g}:{p}" for g in f.get("groups", []) for p in groups.get(g, []) if p in prof})
        if lost:
            totals["profile_blocks_lost"] += 1
            lines.append(f"group blocks matched by profile stop applying: {', '.join(lost)}")
        for k, why in IGNORED_CLIENT.items():
            if k in cl and k not in ("config-profile",):
                default = {"notify_time": 10, "auto_restart": "yes"}.get(k)
                if default is not None and str(cl[k]) != str(default):
                    totals["changed_settings"] += 1
                    lines.append(f"{k}={cl[k]} on 4.x becomes {default} on 5.0 ({why})")
        buf = f.get("buffer") or {}
        if isinstance(buf, dict) and buf.get("queue_size") and str(buf.get("queue_size")) != "5000":
            lines.append(f"client_buffer queue_size={buf['queue_size']} is ignored by 5.0 (batching replaces it)")
        print(f"{aid} {f.get('name')}: " + ("; ".join(lines) if lines else "nothing a 5.0 agent loses beyond deprecated options"))
    print(f"\n{totals['agents']} agents planned: {totals['multi_address']} with several manager addresses, "
          f"{totals['profile_blocks_lost']} lose profile-targeted group blocks, {totals['changed_settings']} non-default settings 5.0 ignores")
    print("The group configuration cannot carry any of these (in agent.conf <agent> accepts only <batch>); the endpoint converter "
          "agent-conf-5x.py, run after the upgrade, does.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["preflight", "run", "status", "report", "legacy-status", "trust-audit", "conf-plan"])
    g = ap.add_argument_group("values the operator supplies")
    g.add_argument("--api", default="https://localhost:55000", help="5.0 manager API (1)")
    g.add_argument("--user", default="wazuh", help="API user (2)")
    g.add_argument("--password-file", help="file with the API password; else env WAZUH_API_PASSWORD (3)")
    g.add_argument("--ca", help="CA that signs the API certificate, e.g. /etc/wazuh-manager/export/ca.pem (4)")
    g.add_argument("--macos-anchor-placed", action="store_true",
                   help="the manager CA was placed by hand on the macOS agents: do not skip them when <ca_delivery> is off (mac1)")
    g.add_argument("--fleet-facts", help="JSON written by fleet-facts-4x.py on the 4.x manager: the address each agent dials, openssl, protocol (5)")
    g.add_argument("--wpk-repo", help="where the manager fetches the 5.0 packages; default: its <wpk_repository> or packages.wazuh.com/5.x/wpk/ (6)")
    g.add_argument("--state", default="fleet-upgrade-state.json", help="state file; the memory that makes re-runs safe (7)")
    g.add_argument("--indexer", help="optional: indexer URL, e.g. https://localhost:9200, to read what each upgraded agent reports about its own TLS verification (8)")
    g.add_argument("--indexer-user", default="admin", help="indexer user with read access to wazuh-agent-config (9)")
    g.add_argument("--indexer-password-file", help="file with its password; else env WAZUH_INDEXER_PASSWORD (10)")
    g.add_argument("--indexer-ca", help="CA that signs the indexer certificate (11)")
    t = ap.add_argument_group("tuning (defaults are meant to be right)")
    t.add_argument("--target", help="target version, default: the manager's own")
    t.add_argument("--step-version", help="4.14.x version for agents below 4.14.0; default: newest 4.14.x in the 4.x repository")
    t.add_argument("--step-wpk-repo", help="repository for the 4.14.x step; default packages.wazuh.com/4.x/wpk/")
    t.add_argument("--always-name-repo", action="store_true", help="send wpk_repo even for packages.wazuh.com")
    t.add_argument("--package-type", choices=["deb", "rpm"], help="for distributions the manager cannot classify")
    t.add_argument("--agents", type=lambda s: s.split(","), help="only these agent ids")
    t.add_argument("--groups", type=lambda s: s.split(","), help="only agents in these groups")
    t.add_argument("--batch-size", type=int, default=50, help="most agents with an undelivered request at any moment")
    t.add_argument("--batch-safety", type=float, default=2.0, help="divide the computed safe batch by this")
    t.add_argument("--canary-key", choices=["platform", "platform-arch"], default="platform")
    t.add_argument("--no-canary-gate", action="store_true")
    t.add_argument("--max-failure-ratio", type=float, default=0.1, help="stop asking when more than this share of finished non-canary agents failed")
    t.add_argument("--min-sample", type=int, default=5, help="finished non-canary agents needed before the failure ratio counts")
    t.add_argument("--poll-interval", type=int, help="override remoted.legacy_task_polling_interval read from the manager")
    t.add_argument("--sweep-allowance", type=int, default=300, help="seconds allowed for remoted to walk the wave after a poll")
    t.add_argument("--install-grace", type=int, default=600, help="seconds from delivery until an agent must report the new version")
    t.add_argument("--restart-window", type=int, default=120, help="a keepalive this long after delivery means the old agent is still running")
    t.add_argument("--push-retry-grace", type=int, default=120)
    t.add_argument("--check-every", type=int, default=30)
    t.add_argument("--max-wait", type=int, default=6 * 3600)
    t.add_argument("--once", action="store_true", help="one pass: request what is due, verify, report, exit")
    t.add_argument("--leave-disconnected", type=int, default=180,
                   help="stop when every open agent has only been waiting for its host to connect for this long (seconds)")
    t.add_argument("--include-disconnected", action="store_true", help="request agents that are not active (default: skip them)")
    t.add_argument("--pending-wait", type=int, default=PENDING_WAIT, help="seconds to wait for agents listed as 'pending'")
    t.add_argument("--include-stale", action="store_true", help="(ag1) request 'active' agents whose last keepalive is old")
    t.add_argument("--allow-cert-mismatch", action="store_true", help="request agents whose dialed address is not in the listener certificate")
    t.add_argument("--node-address", action="append", metavar="NODE=ADDR",
                   help="an address that reaches only NODE (a per-node DNS name or NAT address the tool cannot resolve); an agent "
                        "dialling it is checked against that node's certificate only")
    t.add_argument("--ignore-blockers", action="store_true")
    t.add_argument("--listener-host", help="host to probe for the agent listener; default: the API host")
    t.add_argument("--manager-log", help="read remoted's lines from this file instead of the API (when run on the manager)")
    t.add_argument("--tasks-db", help="also refuse to request an agent with a pending task in this tasks.db (run on the manager, as root)")
    t.add_argument("--insecure", action="store_true", help="do not verify the API certificate")
    t.add_argument("--indexer-insecure", action="store_true", help="do not verify the indexer certificate")
    t.add_argument("--config-report-grace", type=int, default=180, help="seconds to wait for an upgraded agent's configuration report")
    t.add_argument("--slow-push-limit", type=int, default=1800, help="(a5) how long a push may run while the agent keeps sending keepalives before it counts as no-answer")
    t.add_argument("--dry-run", action="store_true")
    t.add_argument("--report", help="also write the report as JSON to this file")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(line_buffering=True)      # a run is usually watched through a log file
    except AttributeError:
        pass

    if a.command == "report":
        return report(load_state(a.state), a)
    pw = open(a.password_file).read().strip() if a.password_file else os.environ.get("WAZUH_API_PASSWORD")
    if not pw:
        sys.exit("no API password: set WAZUH_API_PASSWORD or --password-file")
    api = Api(a.api, a.user, pw, a.ca, a.insecure)
    facts = None
    if a.fleet_facts:
        with open(a.fleet_facts) as fh:
            facts = json.load(fh).get("agents", {})
    global INDEXER
    if a.indexer:
        ipw = open(a.indexer_password_file).read().strip() if a.indexer_password_file else os.environ.get("WAZUH_INDEXER_PASSWORD")
        if not ipw:
            sys.exit("no indexer password: set WAZUH_INDEXER_PASSWORD or --indexer-password-file")
        INDEXER = Indexer(a.indexer, a.indexer_user, ipw, a.indexer_ca, a.indexer_insecure)
    if a.command == "trust-audit":
        return trust_audit(api, parse_node_addresses(a.node_address))
    if a.command == "conf-plan":
        return conf_plan(api, facts, a.agents)
    if a.command == "preflight":
        p = preflight(api, a, facts)
        print_preflight(p)
        sys.exit(1 if p["problems"] else 0)
    if a.command == "legacy-status":
        return legacy_status(api)
    if a.command == "status":
        st = load_state(a.state)
        st.setdefault("nodes", ["node01"])
        verify(api, st, a)
        save_state(a.state, st)
        return report(st, a)
    run(api, a, facts)


if __name__ == "__main__":
    main()
