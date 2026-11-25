#!/usr/bin/env python3
"""identity_stage.py - G5's fixed identity stage: preflight, import, repair until equal, at size.
Merged tool: G5's stage (G1's repair_memberships folded in by G5) plus F7's cut-import key check (rule 5).

Runs as root on the 5.0 manager with the manager's own Python (standard library, plus PyYAML that the
manager bundles, only to rewrite api.yaml when the limit is raised). Reads an export bundle of
wazuh-migrate-identity.py (manifest.json, authd.pass, rbac.db, groups/<g>/<sca policy>).

    identity_stage.py preflight <bundle> [--state DIR] [--with-password] [--with-rbac]
    identity_stage.py run <bundle> --state DIR [--limit-mode stock|raise] [--with-password] [--with-rbac]
                          [--workers N] [--max-passes N] [--stop-after STEP]
    identity_stage.py verify <bundle> --state DIR          (read only: target vs bundle)
    run and verify also take --expected-conf FILE: the settings stage's record of the agent.conf files its pre-upgrade
    pass uploaded (settings/groups-pre/uploaded.json); for those groups that file is the expected content, not the
    bundle's (E2 fold). Without it the stage compares with its own bundle only.
    identity_stage.py restore-limit --state DIR             (put the saved api.yaml back and restart)

What it does differently from the identity tool's import (G1's findings):
  * every list is paged (offset/limit 500 until total_affected_items);
  * the token is renewed before 600 s of age and once more on a 401;
  * a client-side pacer keeps it under the API's requests per minute (the 5.0 limit is a fixed 60 s
    window per client address); a 429 that still happens is waited out, never counted as a failure;
  * no single refusal is fatal: refused items are collected and reported, and the gate names them;
  * agent.conf is uploaded only where it says something (the 4.x stock template is not uploaded);
    5.0's own verify-agent-conf checks every carried file in the preflight, before anything is written;
  * group names over 128 characters are created with the manager's own agent_groups CLI;
  * memberships are assigned with the bulk endpoint in rounds (round p = every agent's p-th group);
  * agents are never deleted; an id 5.0 still refuses (1763) is retried later, not re-imported;
  * the limit, when raised for the import, is saved first and restored before the stage ends; a rerun
    after a kill restores it; the clean restart that restores it also applies the carried secrets;
  * after that restart the target is compared with the bundle again, and repaired if it differs.
State and journal live in --state (one JSON file, one NDJSON journal, the saved api.yaml).
"""
import argparse
import base64
import collections
import concurrent.futures as cf
import contextlib
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HOME = "/var/wazuh-manager"
CONF = "/etc/wazuh-manager"
API_YAML = HOME + "/api/configuration/api.yaml"
RBAC_DB = HOME + "/api/configuration/security/rbac.db"
SHARED = CONF + "/shared"
CREDENTIALS_ENV = CONF + "/export/credentials.env"
CONTROL = HOME + "/bin/wazuh-manager-control"
AGENT_GROUPS = HOME + "/bin/agent_groups"
VERIFY_CONF = HOME + "/bin/verify-agent-conf"
RBAC_CONTROL = HOME + "/bin/rbac_control"
DEFAULT = "default"
API_NAME_MAX = 128           # POST /groups maxLength (4.x and 5.0); the CLI takes 255
GROUPS_PER_AGENT_MAX = 128   # MAX_GROUPS_PER_MULTIGROUP, 4.x and 5.0
CONF_SIZE_WARN = 6 * 1024 * 1024   # G1: 10.4 MB timed out at request_timeout 10 s; 6.1 MB took 6.5 s
AUTHD_PASS_MIN = 16
T0 = time.time()


def log(msg):
    print("%s +%6.0fs %s" % (time.strftime("%H:%M:%S"), time.time() - T0, msg), flush=True)


# --------------------------------------------------------------------------- durable files
def durable_write(path, data, ref_stat=None, tmp_suffix=".tmp"):
    """E2 fold (E2-rpm fix 03, the identity stage's part): write beside the file, fsync, rename, fsync the directory.
    A power cut 0.25 s after the stage ended left its state.json, its saved original api.yaml, the live api.yaml and
    authd.pass 0 bytes (XFS keeps renamed files' data in memory up to 30 s); a rerun would then have restored an empty
    api.yaml. Nothing this stage writes may be renamed into place before its data is on disk."""
    tmp = path + tmp_suffix
    with open(tmp, "wb") as h:
        h.write(data if isinstance(data, bytes) else data.encode())
        h.flush()
        os.fsync(h.fileno())
    if ref_stat is not None:
        chown_like(tmp, ref_stat)
    os.replace(tmp, path)
    try:
        fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


# --------------------------------------------------------------------------- state and journal
class State:
    def __init__(self, path):
        self.dir = path
        os.makedirs(path, mode=0o700, exist_ok=True)
        self.file = os.path.join(path, "state.json")
        self.journal_path = os.path.join(path, "journal.ndjson")
        self.saved_yaml = os.path.join(path, "api.yaml.orig")
        self.lock = threading.Lock()
        self.data = {"runs": [], "steps": {}}
        if os.path.isfile(self.file):
            try:
                self.data = json.load(open(self.file))
            except ValueError:
                # E2 fold: a state file emptied by a power cut (written before this stage synced its files) is set aside,
                # not a traceback on every rerun; the saved original api.yaml is checked on its own (check_saved_original)
                aside = "%s.damaged-%s" % (self.file, time.strftime("%Y%m%d%H%M%S"))
                os.replace(self.file, aside)
                self.data["damaged_state"] = aside
                log("state: %s could not be read (%d bytes; a power cut?): set aside as %s, starting a new state"
                    % (self.file, os.path.getsize(aside), aside))

    def save(self):
        durable_write(self.file, json.dumps(self.data, indent=1, sort_keys=True))

    def will_write(self, what):
        """E3 fold (E3-deb N1): recorded before the first write a restart must follow (a secret, a group, its files, an
        agent, a membership), so a killed run's writes are still restarted for by the rerun. Cleared by a restart."""
        if self.data.get("restart_pending"):
            return
        with self.lock:
            if not self.data.get("restart_pending"):
                self.data["restart_pending"] = what
                self.save()

    def journal(self, **rec):
        rec["t"] = round(time.time(), 3)
        with self.lock:
            with open(self.journal_path, "a") as h:
                h.write(json.dumps(rec) + "\n")
                # E4-rpm gap 5: on disk before the stage goes on (after two cuts the journal was 0 bytes, its lines lost)
                h.flush()
                os.fsync(h.fileno())

    def step(self, name, **info):
        self.data["steps"][name] = dict(info, at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        self.save()


# --------------------------------------------------------------------------- the API
def env_value(key, path=CREDENTIALS_ENV):
    value = None
    try:
        for line in open(path):
            name, _, raw = line.strip().partition("=")
            if name.strip() == key:
                value = raw.strip().strip("'\"")
    except OSError:
        pass
    return value


class Api:
    """Server API client: paging, token renewal, pacing under the per-minute limit, 429 waits, retries
    through a manager restart. Thread safe (inserts may run on several workers)."""

    def __init__(self, per_minute, url="https://localhost:55000", user="wazuh", password=None,
                 ca=CONF + "/certs/root-ca.pem", token_max_age=600):
        self.url = url.rstrip("/")
        self.user = user
        self.password = password or os.environ.get("WAZUH_API_PASSWORD") or env_value("WAZUH_MANAGER_API_PASSWORD")
        self.ctx = ssl.create_default_context(cafile=ca) if ca and os.path.exists(ca) else ssl._create_unverified_context()
        self.ctx.check_hostname = False   # loopback; the certificate names the manager, not localhost
        self.token, self.token_at = None, 0
        self.token_max_age = token_max_age
        self.lock = threading.Lock()
        self.auth_lock = threading.Lock()
        self.sent = collections.deque()
        self.set_budget(per_minute)
        self.stats = collections.Counter()
        self.waits = collections.Counter()

    def set_budget(self, per_minute):
        # 3 % head room under the server's count; 0 = the limit is off, no pacing
        self.budget = 0 if not per_minute else max(1, int(per_minute * 0.97))

    def pace(self):
        if not self.budget:
            return
        while True:
            with self.lock:
                now = time.time()
                while self.sent and now - self.sent[0] >= 60.0:
                    self.sent.popleft()
                if len(self.sent) < self.budget:
                    self.sent.append(now)
                    return
                wait = 60.0 - (now - self.sent[0]) + 0.05
            self.waits["pacer_s"] += wait
            time.sleep(wait)

    def authenticate(self):
        req = urllib.request.Request(self.url + "/security/user/authenticate?raw=true", method="POST")
        req.add_header("Authorization", "Basic " + base64.b64encode(
            ("%s:%s" % (self.user, self.password)).encode()).decode())
        for attempt in range(120):
            self.pace()
            self.stats["login"] += 1
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
                    self.token, self.token_at = r.read().decode().strip(), time.time()
                    return
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    self.stats["429"] += 1
                    self.waits["429_s"] += 5
                    time.sleep(5)
                    continue
                raise SystemExit("API login as %s failed: HTTP %s %s" % (self.user, e.code, e.read()[:200]))
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                self.stats["conn_retry"] += 1
                time.sleep(5)       # the API is restarting
        raise SystemExit("API login: the API did not answer for 10 minutes")

    def _token(self):
        with self.auth_lock:     # one login at a time; the others wait for its token
            if not self.token or time.time() - self.token_at > self.token_max_age:
                self.authenticate()
            return self.token

    def call(self, method, path, body=None, ctype="application/json", timeout=120):
        data = None
        if body is not None:
            data = json.dumps(body).encode() if ctype == "application/json" else (
                body.encode() if isinstance(body, str) else body)
        reauthed = False
        for attempt in range(400):
            token = self._token()
            self.pace()
            req = urllib.request.Request(self.url + path, data=data, method=method)
            req.add_header("Content-Type", ctype)
            req.add_header("Authorization", "Bearer " + token)
            self.stats["requests"] += 1
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as r:
                    raw = r.read().decode()
                    if "json" not in (r.headers.get("Content-Type") or "application/json"):
                        return r.status, {"__raw": raw}
                    return r.status, json.loads(raw or "{}")
            except urllib.error.HTTPError as e:
                txt = e.read().decode(errors="replace")
                try:
                    payload = json.loads(txt)
                except ValueError:
                    payload = {"detail": txt[:300]}
                if e.code == 401 and not reauthed:
                    self.stats["reauth"] += 1
                    with self.lock:
                        self.token = None
                    reauthed = True
                    continue
                if e.code == 429:
                    # someone else on this address, or a window we did not see start: wait, never fail
                    self.stats["429"] += 1
                    w = 3 + min(attempt, 10)
                    self.waits["429_s"] += w
                    time.sleep(w)
                    continue
                return e.code, payload
            except (TimeoutError, urllib.error.URLError, ConnectionError, OSError) as e:
                self.stats["conn_retry"] += 1
                timeout = min(timeout * 2, 1800) if "timed out" in str(e) else timeout
                time.sleep(3)
                continue
        return 0, {"detail": "gave up after retries"}

    @staticmethod
    def ok(status, payload):
        return 0 < status < 300 and payload.get("error", 0) == 0 and not (payload.get("data") or {}).get("failed_items")

    def all_items(self, path, page=500):
        sep = "&" if "?" in path else "?"
        items, offset, total = [], 0, None
        while total is None or offset < total:
            status, payload = self.call("GET", "%s%soffset=%d&limit=%d" % (path, sep, offset, page))
            if status >= 300 or status == 0:
                raise SystemExit("GET %s failed: HTTP %s %s" % (path, status, json.dumps(payload)[:300]))
            data = payload["data"]
            total = data["total_affected_items"]
            batch = data["affected_items"]
            items.extend(batch)
            if not batch:
                break
            offset += len(batch)
        return items


def q(name):
    return urllib.parse.quote(name, safe="")


# --------------------------------------------------------------------------- agent.conf comparisons
def strip_conf(text):
    """Without the XML declaration, comments and blank lines; each line stripped (5.0 re-indents)."""
    text = re.sub(r"^﻿?\s*<\?xml[^>]*\?>", "", text or "")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def is_empty_conf(text):
    """Says nothing: only empty <agent_config> elements (the 4.x 76-byte template, the 5.0 2,127-byte one)."""
    rest = re.sub(r"<agent_config(\s[^>]*)?>\s*</agent_config>|<agent_config(\s[^>]*)?/>", "", strip_conf(text))
    return not rest.strip()


def conf_equal(a, b):
    if is_empty_conf(a) and is_empty_conf(b):
        return True
    return strip_conf(a) == strip_conf(b)


def read_file(path):
    try:
        with open(path, errors="replace") as h:
            return h.read()
    except OSError:
        return None


# --------------------------------------------------------------------------- the bundle
def load_bundle(bundle):
    m = json.load(open(os.path.join(bundle, "manifest.json")))
    for g in m["groups"]:
        g.setdefault("sca_policies", [])
    want = {"%03d" % a["id"]: list(a.get("groups") or [DEFAULT]) for a in m["agents"]}
    by_id = {"%03d" % a["id"]: a for a in m["agents"]}
    return m, want, by_id


def load_expected(path):
    """E2 fold (E2-rpm fix 06, E2-deb fix 1, reconciled): {group: agent.conf text} the flow's pre-upgrade group pass
    uploaded on purpose after the import (settings_stage.py record_upload). For those groups it is the content 5.0 must
    hold: the verify accepts it, and a repair writes it, never the bundle's 4.x file (which holds the option every 4.x
    agent of the group refuses, prefilter_cmd). Exact group names from the record, not a directory glob."""
    if not path:
        return {}
    try:
        d = json.load(open(path))
    except (OSError, ValueError):
        return {}
    out = {}
    for g, v in d.items():
        if isinstance(v, dict) and v.get("agent_conf"):
            text = read_file(os.path.join(os.path.dirname(os.path.abspath(path)), v["agent_conf"]))
            if text is not None:
                out[g] = text
    return out


def read_api_yaml_limit():
    """The limit api.yaml sets (300 when absent). 5.0 has no endpoint that reports it (404)."""
    try:
        import yaml
        conf = yaml.safe_load(open(API_YAML)) or {}
    except Exception:
        return 300, None
    v = (conf.get("access") or {}).get("max_request_per_minute", 300)
    return int(v), conf


# --------------------------------------------------------------------------- preflight
def preflight(bundle, args, api=None, quiet=False):
    """Every reason to refuse or to set aside, before the first write. Returns a report dict."""
    m, want, by_id = load_bundle(bundle)
    rep = {"agents": len(m["agents"]), "groups": len(m["groups"]), "memberships": sum(len(v) for v in want.values()),
           "blockers": [], "set_aside": {}, "cli_groups": [], "conf_refused": {}, "conf_large": [],
           "conf_to_upload": [], "notes": []}
    names = collections.Counter(a["name"] for a in m["agents"])
    dup = [n for n, c in names.items() if c > 1]
    if dup:
        rep["blockers"].append("agent names used twice: %s" % dup[:5])
    bad_keys = [a for a, v in by_id.items() if not re.fullmatch(r"[0-9a-fA-F]{32,128}", v.get("key") or "")]
    if bad_keys:
        rep["blockers"].append("agents without a usable key: %s" % bad_keys[:5])
    gnames = {g["name"] for g in m["groups"]} | {DEFAULT}
    unknown = sorted({g for v in want.values() for g in v} - gnames)
    if unknown:
        rep["blockers"].append("memberships name groups the bundle does not carry: %s" % unknown[:5])
    too_many = [a for a, v in want.items() if len(v) > GROUPS_PER_AGENT_MAX]
    if too_many:
        rep["blockers"].append("agents in more than %d groups: %s" % (GROUPS_PER_AGENT_MAX, too_many[:5]))
    rep["cli_groups"] = [g["name"] for g in m["groups"] if len(g["name"]) > API_NAME_MAX]
    # every carried agent.conf through 5.0's own validator (what PUT /groups/{g}/configuration runs)
    t = time.time()
    with tempfile.TemporaryDirectory(prefix="g5-conf-") as tmp:
        for g in m["groups"]:
            text = g.get("agent_conf") or ""
            if is_empty_conf(text):
                continue
            rep["conf_to_upload"].append(g["name"])
            if len(text.encode()) > CONF_SIZE_WARN:
                rep["conf_large"].append([g["name"], len(text.encode())])
            path = os.path.join(tmp, "agent.conf")
            with open(path, "w") as h:
                h.write(text)
            r = subprocess.run([VERIFY_CONF, "-f", path], capture_output=True, text=True, timeout=120)
            out = (r.stdout + r.stderr).strip()
            if r.returncode != 0 or "ERROR" in out:
                rep["conf_refused"][g["name"]] = out.splitlines()[-1][:300] if out else "exit %d" % r.returncode
    rep["conf_check_s"] = round(time.time() - t, 1)
    for name in rep["conf_refused"]:
        rep["set_aside"][name] = "agent.conf refused by 5.0's verify-agent-conf: the group is created and its agents" \
                                 " assigned, the 5.0 template is kept; a person cleans the file (C1's cleaner) and uploads it"
    # secrets
    if args.with_password:
        p = os.path.join(bundle, "authd.pass")
        if not os.path.isfile(p):
            rep["blockers"].append("--with-password: the bundle has no authd.pass")
        else:
            line = open(p, "rb").readline().rstrip(b"\r\n")
            if len(line) < AUTHD_PASS_MIN:
                rep["blockers"].append("--with-password: the enrollment password is %d bytes, 5.0 needs %d" % (len(line), AUTHD_PASS_MIN))
            rep["password_bytes"] = len(line)
    if args.with_rbac:
        p = os.path.join(bundle, "rbac.db")
        if not os.path.isfile(p):
            rep["blockers"].append("--with-rbac: the bundle has no rbac.db")
        else:
            with contextlib.closing(sqlite3.connect("file:%s?mode=ro" % p, uri=True)) as c:
                rep["rbac"] = {t: c.execute("select count(*) from %s" % t).fetchone()[0]
                               for t in ("users", "roles", "policies", "rules", "user_roles", "roles_policies")}
                rep["rbac"]["user_names"] = [r[0] for r in c.execute("select username from users order by id")]
    # the target
    limit, _ = read_api_yaml_limit()
    rep["api_limit_per_minute"] = limit
    if api is not None:
        have = {i["id"]: i.get("name") for i in api.all_items("/agents?select=id,name") if i["id"] != "000"}
        groups = {g["name"] for g in api.all_items("/groups?select=name")}
        extra = sorted(set(have) - set(want))
        renamed = sorted(a for a in set(have) & set(want) if have[a] != by_id[a]["name"])
        if extra:
            rep["blockers"].append("the target holds %d agent(s) the bundle does not carry (first %s): a person decides"
                                   % (len(extra), extra[:5]))
        if renamed:
            rep["blockers"].append("%d agent id(s) on the target carry another name (first %s)" % (len(renamed), renamed[:5]))
        rep["target"] = {"agents_present": len(have), "groups_present": len(groups)}
        missing_groups = len(gnames - groups)
        missing_agents = len(set(want) - set(have))
        n_conf = len(rep["conf_to_upload"]) - len(rep["conf_refused"])
        # membership calls: distinct (position, group) pairs, 500 agents per call (G1's planner on a fresh insert)
        pairs = collections.Counter()
        for v in want.values():
            for p, g in enumerate(v):
                if p == 0 and g == DEFAULT:
                    continue
                pairs[(p, g)] += 1
        mcalls = sum((c + 499) // 500 for c in pairs.values())
        reads = 2 * (len(want) // 500 + 2 + len(gnames) // 500 + 2)
        total = missing_groups + n_conf + missing_agents + mcalls + reads
        rep["estimate"] = {"requests": total, "group_creates": missing_groups, "conf_uploads": n_conf,
                           "inserts": missing_agents, "membership_calls_fresh": mcalls, "reads": reads,
                           "minutes_at_limit": round(total / (limit * 0.97), 1) if limit else None,
                           "minutes_at_300": round(total / 291.0, 1)}
    if not quiet:
        log("preflight: %d agents, %d groups, %d memberships; blockers %d; set aside %d; groups via CLI %d; "
            "agent.conf to upload %d (refused %d, over 6 MB %d, checked in %ss); limit %s/min; estimate %s" % (
                rep["agents"], rep["groups"], rep["memberships"], len(rep["blockers"]), len(rep["set_aside"]),
                len(rep["cli_groups"]), len(rep["conf_to_upload"]), len(rep["conf_refused"]), len(rep["conf_large"]),
                rep["conf_check_s"], limit, json.dumps(rep.get("estimate"))))
        for b in rep["blockers"]:
            log("  BLOCKER: " + b)
        for g, why in rep["conf_refused"].items():
            log("  set aside: group %s: %s" % (g[:60], why))
    return rep


# --------------------------------------------------------------------------- the limit
def chown_like(path, ref_stat):
    os.chown(path, ref_stat.st_uid, ref_stat.st_gid)
    os.chmod(path, ref_stat.st_mode & 0o7777)


def restart_cmd():
    """OF1 (E2-deb G2): the manager is restarted through its unit, so its daemons run inside wazuh-manager.service.
    `wazuh-manager-control restart` started them in the caller's cgroup: when the flow ran under a systemd unit or a
    session manager that cleans its cgroup, they were killed with it while the unit still said active. The control
    script stays only where there is no systemd (no systemctl, or systemd not running as init: a container)."""
    sc = shutil.which("systemctl")
    if sc and (os.path.isdir("/run/systemd/system") or os.environ.get("MIG_ASSUME_SYSTEMD") == "1"):
        return [sc, "restart", "wazuh-manager"]
    return [CONTROL, "restart"]


def will_write(st, what):
    """State.will_write when st is a State (some callers pass a bare namespace)."""
    f = getattr(st, "will_write", None)
    if f:
        f(what)


def restart_manager(st, why):
    t = time.time()
    cmd = restart_cmd()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        log("manager restart (%s) with %s: exit %d %s" % (why, " ".join(cmd), r.returncode, (r.stderr or r.stdout).strip()[-300:]))
    # wait until the API answers again (401 without credentials)
    ctx = ssl._create_unverified_context()
    up = False
    for _ in range(200):
        try:
            urllib.request.urlopen(urllib.request.Request("https://localhost:55000/"), context=ctx, timeout=5)
            up = True
        except urllib.error.HTTPError as e:
            up = e.code == 401
        except Exception:
            up = False
        if up:
            break
        time.sleep(1.5)
    s = round(time.time() - t, 1)
    st.journal(action="restart", why=why, cmd=" ".join(cmd), rc=r.returncode, seconds=s, api_up=up)
    log("manager restart (%s): exit %d, API answering after %ss" % (why, r.returncode, s))
    if not up:
        raise SystemExit("the API did not come back after the restart")
    if r.returncode == 0 and st.data.pop("restart_pending", None):
        st.save()           # E3 fold (N1): everything written before this restart is applied
    return s


RAISED_MARK = "# raised for the identity import by identity_stage.py"


def check_saved_original(st):
    """E2 fold (E2-rpm fix 03's open gap): the saved original api.yaml must be intact before anything restores it or
    raises from it. Intact: not empty and, when the state recorded it, the same sha256. Damaged, with a live api.yaml that
    is not this stage's raised copy: the live file is the original (the cut came before the raise reached the disk, or
    after the restore), so it is saved again. Damaged, with the live file raised or empty: the original is lost; stop,
    never write an empty or guessed api.yaml."""
    if not os.path.isfile(st.saved_yaml):
        return
    data = open(st.saved_yaml, "rb").read()
    want = (st.data.get("limit") or {}).get("saved_sha")
    if data and (not want or hashlib.sha256(data).hexdigest() == want):
        return
    try:
        live = open(API_YAML, "rb").read()
    except OSError:
        live = b""
    if live.strip() and not live.startswith(RAISED_MARK.encode()):
        durable_write(st.saved_yaml, live)
        lim = st.data.setdefault("limit", {})
        lim.update(saved_sha=hashlib.sha256(live).hexdigest(), resaved_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   resaved_why="the saved original was %d bytes%s; the live api.yaml is not the raised copy" %
                   (len(data), ", not the sha256 recorded" if data else ""))
        if lim.get("state") == "raised":
            lim.pop("state")
        st.save()
        st.journal(action="limit_original_resaved", bytes_before=len(data))
        log("limit: the saved original api.yaml was damaged (%d bytes); the live api.yaml is not raised, so it is the "
            "original: saved again" % len(data))
        return
    st.journal(action="limit_original_lost", saved_bytes=len(data), live_bytes=len(live))
    raise SystemExit("the saved original api.yaml %s is damaged (%d bytes%s) and the live %s is %s: the original cannot be "
                     "put back automatically. Restore %s from your own copy (the 5.0 package's file plus your changes), "
                     "delete %s, then run this stage again" % (
                         st.saved_yaml, len(data), ", sha256 differs from the recorded one" if data else "", API_YAML,
                         "empty" if not live.strip() else "the copy this stage raised", API_YAML, st.saved_yaml))


def raise_limit(st, value):
    """Save api.yaml once (never overwrite the saved original), set access.max_request_per_minute, restart."""
    import yaml
    check_saved_original(st)
    cur = open(API_YAML, "rb").read()
    if not os.path.isfile(st.saved_yaml):
        durable_write(st.saved_yaml, cur)       # on disk before api.yaml changes (E2 fold)
        st.data["limit"] = {"saved_sha": hashlib.sha256(cur).hexdigest(), "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        st.save()
    # E2 fold: built from the saved original, never from the live file: after a cut the live file can be empty or the
    # raised copy, and a raise built on an empty file would drop every other setting of api.yaml
    conf = yaml.safe_load(open(st.saved_yaml, "rb").read()) or {}
    live = yaml.safe_load(cur) if cur.strip() else None
    if ((live or {}).get("access") or {}).get("max_request_per_minute") == value:
        log("limit: already raised to %s by an earlier run" % value)
        st.data.setdefault("limit", {}).update(raised_to=value, state="raised")
        st.save()
        return 0.0
    conf.setdefault("access", {})["max_request_per_minute"] = value
    ref = os.stat(API_YAML)
    body = "%s; the original is saved in %s\n" % (RAISED_MARK, st.saved_yaml) + yaml.safe_dump(conf, default_flow_style=False)
    durable_write(API_YAML, body, ref, ".g5tmp")
    st.data.setdefault("limit", {})["raised_to"] = value
    st.data["limit"]["state"] = "raised"
    st.save()
    st.journal(action="limit_raise", value=value)
    return restart_manager(st, "limit raised to %s" % value)


def put_back_yaml(st):
    """Restore the saved api.yaml bytes (no restart). Returns True if it changed anything."""
    if not os.path.isfile(st.saved_yaml):
        return False
    check_saved_original(st)        # E2 fold: never put back an empty or damaged copy
    saved = open(st.saved_yaml, "rb").read()
    cur = open(API_YAML, "rb").read()
    if cur == saved:
        st.data.setdefault("limit", {})["state"] = "restored"
        st.save()
        return False
    ref = os.stat(API_YAML)
    durable_write(API_YAML, saved, ref, ".g5tmp")
    st.data.setdefault("limit", {})["state"] = "restored-pending-restart"
    st.save()
    st.journal(action="limit_restore_file")
    return True


# --------------------------------------------------------------------------- the import steps
def read_registry(api):
    agents = {}
    for item in api.all_items("/agents?select=id,name,group"):
        if item["id"] != "000":
            agents[item["id"]] = {"name": item.get("name"), "groups": list(item.get("group") or [])}
    groups = {g["name"] for g in api.all_items("/groups?select=name")}
    return agents, groups


def install_policy(bundle, group, name):
    src = os.path.join(bundle, "groups", group, name)
    dst = os.path.join(SHARED, group, name)
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o660)
    try:
        os.chown(dst, pwd.getpwnam("wazuh-manager").pw_uid, grp.getgrnam("wazuh-manager").gr_gid)
    except KeyError:
        pass


def do_groups(api, st, bundle, m, groups_present, refused, res, expected=None):
    t = time.time()
    for g in m["groups"]:
        if g["name"] in groups_present:
            continue
        will_write(st, "group %s" % g["name"][:80])
        s, p = api.call("POST", "/groups", {"group_id": g["name"]})
        how = "api"
        if not Api.ok(s, p) and len(g["name"]) > API_NAME_MAX:
            r = subprocess.run([AGENT_GROUPS, "-a", "-g", g["name"], "-q"], capture_output=True, text=True)
            s, p, how = (200, {}, "cli") if r.returncode == 0 else (500, {"detail": (r.stdout + r.stderr)[:200]}, "cli")
        ok = Api.ok(s, p) or (how == "cli" and s == 200)
        st.journal(action="group", group=g["name"][:80], how=how, status=s, ok=ok, detail=(p.get("detail") or "")[:200])
        res["group_failed" if not ok else "group_created"] += 1
        if ok:
            groups_present.add(g["name"])
    t_groups = time.time() - t
    t = time.time()
    for g in m["groups"] + ([m["default_group"]] if m.get("default_group") else []):
        for n in g.get("sca_policies", []):
            if g["name"] in groups_present and not os.path.isfile(os.path.join(SHARED, g["name"], n)):
                will_write(st, "policy %s/%s" % (g["name"][:80], n))
                install_policy(bundle, g["name"], n)
                st.journal(action="policy", group=g["name"], file=n)
                res["policy_installed"] += 1
    for g in m["groups"]:
        text = (expected or {}).get(g["name"], g.get("agent_conf") or "")   # E2 fold: the pass's output where it cleaned the group
        if g["name"] not in groups_present or g["name"] in refused:
            continue
        cur = read_file(os.path.join(SHARED, g["name"], "agent.conf"))
        if cur is not None and conf_equal(text, cur):
            continue
        will_write(st, "agent.conf of %s" % g["name"][:80])
        s, p = api.call("PUT", "/groups/%s/configuration" % q(g["name"]), text, ctype="application/xml", timeout=300)
        ok = Api.ok(s, p)
        st.journal(action="conf", group=g["name"][:80], status=s, ok=ok, bytes=len(text.encode()),
                   detail=(p.get("detail") or "")[:300])
        res["conf_uploaded" if ok else "conf_failed"] += 1
    # the 4.x default group's agent.conf, when it says something: appended after the 5.0 one (the identity tool's way)
    d = m.get("default_group") or {}
    if d.get("customized") and not is_empty_conf(d.get("agent_conf") or ""):
        cur = read_file(os.path.join(SHARED, DEFAULT, "agent.conf")) or ""
        carried = re.sub(r"\A﻿?\s*<\?xml[^>]*\?>", "", d["agent_conf"]).strip()
        if strip_conf(carried) not in strip_conf(cur):
            merged = "%s\n\n<!-- Carried from the 4.x default group by identity_stage.py -->\n%s\n" % (cur.rstrip(), carried)
            will_write(st, "agent.conf of %s" % DEFAULT)
            s, p = api.call("PUT", "/groups/%s/configuration" % DEFAULT, merged, ctype="application/xml", timeout=300)
            st.journal(action="default_merge", status=s, ok=Api.ok(s, p), detail=(p.get("detail") or "")[:300])
            res["default_merged" if Api.ok(s, p) else "default_merge_failed"] += 1
    return t_groups, time.time() - t


def do_inserts(api, st, by_id, missing, workers, res, cooldown_wait):
    t = time.time()
    deferred = []

    def one(aid):
        a = by_id[aid]
        body = {"id": aid, "name": a["name"], "key": a["key"]}
        if a.get("ip"):
            body["ip"] = a["ip"]
        will_write(st, "agent %s" % aid)
        s, p = api.call("POST", "/agents/insert", body)
        return aid, s, p

    def handle(aid, s, p):
        ok = Api.ok(s, p)
        code = p.get("error") if isinstance(p.get("error"), int) else None
        detail = (p.get("detail") or p.get("message") or "")
        if ok:
            res["inserted"] += 1
            return
        if code == 1763 or "cannot be reused yet" in detail:
            deferred.append(aid)
            st.journal(action="insert_deferred", agent=aid, status=s, detail=detail[:200])
            return
        if code == 1708 or "already" in detail.lower():   # present (a resumed run): the repair checks it
            res["insert_present"] += 1
            st.journal(action="insert_present", agent=aid, status=s, detail=detail[:200])
            return
        res["insert_failed"] += 1
        st.journal(action="insert_failed", agent=aid, status=s, detail=detail[:300])

    done = 0
    if workers <= 1:
        for aid in missing:
            handle(*one(aid))
            done += 1
            if done % 2000 == 0:
                log("  inserts: %d of %d (api %s)" % (done, len(missing), dict(api.stats)))
    else:
        with cf.ThreadPoolExecutor(workers) as ex:
            for aid, s, p in ex.map(one, missing):
                handle(aid, s, p)
                done += 1
                if done % 2000 == 0:
                    log("  inserts: %d of %d (api %s)" % (done, len(missing), dict(api.stats)))
    # ids 5.0 still blocks after a deletion (1763): never delete and re-insert; retry until the block ends
    end = time.time() + cooldown_wait
    while deferred and time.time() < end:
        log("  %d insert(s) refused with 1763 (id not reusable yet): retrying in 60 s" % len(deferred))
        time.sleep(60)
        again, deferred[:] = list(deferred), []
        for aid in again:
            handle(*one(aid))
    res["insert_deferred_left"] = len(deferred)
    return time.time() - t


def registry_keys(path=None):
    """{id: (name, key)} of every usable entry of a client.keys (removed entries, `!name`, are not agents)."""
    out = {}
    try:
        for line in open(path or (CONF + "/client.keys"), errors="replace"):
            f = line.split()
            if len(f) >= 4 and f[0].isdigit() and not f[1].startswith(("!", "#")):
                out["%03d" % int(f[0])] = (f[1], f[3])
    except OSError:
        pass
    return out


def cut_import_check(by_id, on_disk):
    """F7 (rule 5): a registry that holds any agent before the import is a cut import only if every entry equals the
    bundle's id, name AND key. Returns (equal, missing, wrong, foreign): wrong are ids whose name or key differ (an agent
    that enrolled by itself under an id the bundle gives to another), foreign are ids the bundle does not carry."""
    want = {i: (a["name"], a["key"]) for i, a in by_id.items()}
    equal = sorted(i for i in want if on_disk.get(i) == want[i])
    missing = sorted(i for i in want if i not in on_disk)
    wrong = sorted(i for i in on_disk if i in want and on_disk[i] != want[i])
    foreign = sorted(i for i in on_disk if i not in want)
    return equal, missing, wrong, foreign


def plan_memberships(want, have):
    plan = {}
    for aid, w in want.items():
        h = have.get(aid)
        if h is None or h == w:
            continue
        if len(h) < len(w) and w[:len(h)] == h:
            plan[aid] = (len(h), False)      # append the tail
        else:
            plan[aid] = (0, True)            # reset to the first group (force_single_group), then append
    return plan


def do_memberships(api, st, want, plan, chunk, res):
    t = time.time()
    calls = 0
    rounds = max((len(want[a]) for a in plan), default=0)
    for pos in range(rounds):
        by_group = collections.defaultdict(list)
        for aid, (start, reset) in plan.items():
            w = want[aid]
            if pos < start or pos >= len(w):
                continue
            by_group[(w[pos], reset and pos == 0)].append(aid)
        for (group, force), ids in sorted(by_group.items()):
            for i in range(0, len(ids), chunk):
                part = ids[i:i + chunk]
                assert part, "an empty agents_list selects every agent"
                path = "/agents/group?group_id=%s&agents_list=%s&wait_for_complete=true" % (q(group), ",".join(part))
                if force:
                    path += "&force_single_group=true"
                will_write(st, "membership of %s" % group[:80])
                s, p = api.call("PUT", path, timeout=300)
                calls += 1
                bad = (p.get("data") or {}).get("failed_items") or []
                ok = 0 < s < 300 and not bad
                res["membership_calls"] += 1
                if not ok:
                    res["membership_calls_failed"] += 1
                    st.journal(action="assign", round=pos, group=group[:80], force=force, agents=len(part), status=s,
                               failed=json.dumps(bad)[:400] if bad else (p.get("detail") or "")[:300])
        log("  memberships round %d done: %d calls so far (api %s)" % (pos, calls, dict(api.stats)))
    return time.time() - t


def compare(api, bundle, m, want, by_id, refused, expected=None):
    """The target against the bundle. Returns (differences dict, have, groups present). `expected` (load_expected):
    groups whose agent.conf the flow's pre-upgrade pass rewrote on purpose; listed in d["conf_cleaned"] when 5.0 holds
    exactly that file, which is not a difference."""
    have, groups = read_registry(api)
    d = {}
    d["groups_missing"] = sorted({g["name"] for g in m["groups"]} - groups)
    conf, cleaned = [], []
    for g in m["groups"]:
        if g["name"] in groups and g["name"] not in refused:
            cur = read_file(os.path.join(SHARED, g["name"], "agent.conf"))
            if cur is not None and g["name"] in (expected or {}) and conf_equal(expected[g["name"]], cur):
                if not conf_equal(g.get("agent_conf") or "", cur):
                    cleaned.append(g["name"])
                continue
            if cur is None or not conf_equal((expected or {}).get(g["name"], g.get("agent_conf") or ""), cur):
                conf.append(g["name"])
    d["conf_differs"] = conf
    d["policies_missing"] = [[g["name"], n] for g in m["groups"] + ([m["default_group"]] if m.get("default_group") else [])
                             for n in g.get("sca_policies", []) if not os.path.isfile(os.path.join(SHARED, g["name"], n))]
    d["agents_missing"] = sorted(set(want) - set(have))
    d["agents_extra"] = sorted(set(have) - set(want))
    d["renamed"] = sorted(a for a in set(want) & set(have) if have[a]["name"] != by_id[a]["name"])
    keys = {i: k for i, (_n, k) in registry_keys().items()}
    d["keys_differ"] = sorted(a for a in set(want) & set(have) if keys.get(a) != by_id[a]["key"])
    cur = {a: v["groups"] for a, v in have.items()}
    d["membership_differs"] = sorted(a for a in want if a in cur and cur[a] != want[a])
    d["conf_cleaned"] = cleaned          # information only: neither repairable() nor the gate counts it
    return d, have, groups


def summary(d):
    return {k: len(v) for k, v in d.items()}


def repairable(d):
    return any(d[k] for k in ("groups_missing", "conf_differs", "policies_missing", "agents_missing", "membership_differs"))


def install_secret(st, bundle, name):
    src = os.path.join(bundle, name)
    dst = CONF + "/authd.pass" if name == "authd.pass" else RBAC_DB
    if os.path.exists(dst) and open(dst, "rb").read() == open(src, "rb").read() and name == "authd.pass":
        return "already"
    will_write(st, name)
    backup = dst + ".pre-migration"
    if os.path.exists(dst):
        if os.path.exists(backup):
            backup = "%s.pre-migration.%s" % (dst, time.strftime("%Y%m%d%H%M%S"))
        shutil.copy2(dst, backup)
    durable_write(dst, open(src, "rb").read())   # E2 fold: authd.pass was 0 bytes after the cut and stopped the manager
    os.chmod(dst, 0o640)
    try:
        os.chown(dst, pwd.getpwnam("wazuh-manager").pw_uid, grp.getgrnam("wazuh-manager").gr_gid)
    except KeyError:
        pass
    if name == "rbac.db":
        with contextlib.closing(sqlite3.connect(dst)) as c:
            c.execute("PRAGMA user_version = 0")     # asks the API to rebuild 5.0's defaults at the next start
            c.commit()
    st.journal(action="secret", name=name, backup=backup)
    return "installed"


def reset_service_passwords(st):
    """After a carried rbac.db the two service users hold their 4.x passwords: set them back to the values the
    5.0 install published (the dashboard was configured with them). P1's im_passwords, with the result checked."""
    t = time.time()
    api_pw = env_value("WAZUH_MANAGER_API_PASSWORD")
    wui_pw = env_value("WAZUH_MANAGER_WUI_PASSWORD")
    last = ""
    for attempt in range(30):
        r1 = subprocess.run([RBAC_CONTROL, "change-password", "-u", "wazuh", "-p", "-"], input=api_pw + "\n",
                            capture_output=True, text=True)
        r2 = subprocess.run([RBAC_CONTROL, "change-password", "-u", "wazuh-internal-client", "-p", "-"],
                            input=wui_pw + "\n", capture_output=True, text=True)
        last = (r1.stdout + r1.stderr + r2.stdout + r2.stderr).strip()[-300:]
        if r1.returncode == 0 and r2.returncode == 0:
            try:
                req = urllib.request.Request("https://localhost:55000/security/user/authenticate?raw=true", method="POST")
                req.add_header("Authorization", "Basic " + base64.b64encode(("wazuh:" + api_pw).encode()).decode())
                with urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=30) as r:
                    if r.read().decode().startswith("ey"):
                        st.journal(action="passwords_reset", attempts=attempt + 1, seconds=round(time.time() - t, 1))
                        return round(time.time() - t, 1)
            except Exception as e:
                last = str(e)[:200]
        time.sleep(5)
    raise SystemExit("could not set the service users back to the published passwords: %s" % last)


def published_login_refused(api):
    """E4-rpm fix 01: True when the API answers 401 to the published credentials (any other failure is raised)."""
    try:
        api.authenticate()
        return False
    except SystemExit as e:
        if "HTTP 401" in str(e):
            return True
        raise


# --------------------------------------------------------------------------- commands
def cmd_preflight(args):
    api = Api(read_api_yaml_limit()[0])
    rep = preflight(args.bundle, args, api)
    if args.state:
        st = State(args.state)
        st.data["preflight"] = rep
        st.save()
    print(json.dumps(rep, indent=1)[:4000])
    return 2 if rep["blockers"] else 0


def cmd_run(args):
    st = State(args.state)
    run = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "mode": args.limit_mode, "workers": args.workers,
           "with_password": args.with_password, "with_rbac": args.with_rbac, "timings": {}, "result": "running"}
    st.data["runs"].append(run)
    st.save()
    tm = run["timings"]
    res = collections.Counter()
    m, want, by_id = load_bundle(args.bundle)

    def done(name, seconds):
        tm[name] = round(seconds, 1)
        st.save()

    # a raised limit left by a killed run stays raised until this run restores it
    left_raised = (st.data.get("limit") or {}).get("state") in ("raised", "restored-pending-restart")
    limit, _ = read_api_yaml_limit()
    api = Api(limit)
    # E4-rpm fix 01: a cut after the carried rbac.db was installed and before reset_service_passwords left 'wazuh' with
    # its 4.x password once the manager started again (a reboot 0.25 s after the original api.yaml was written back):
    # every rerun stopped on "API login as wazuh failed: HTTP 401". With the carried rbac.db in place (install_secret
    # kept the 5.0 one as .pre-migration), the service users are set back to the published passwords first, as the
    # stage does after its own restart.
    if args.with_rbac and os.path.exists(RBAC_DB + ".pre-migration") and published_login_refused(api):
        log("API login as wazuh refused with the published 5.0 password while the carried rbac.db is installed (a cut "
            "before the service passwords were set back): setting the service users back to the published passwords")
        done("service_passwords_reset_on_resume", reset_service_passwords(st))
    t = time.time()
    rep = preflight(args.bundle, args, api)
    st.data["preflight"] = rep
    done("preflight", time.time() - t)
    if rep["blockers"]:
        run["result"] = "refused by the preflight"
        st.save()
        return 2
    refused = set(rep["conf_refused"])

    if args.limit_mode == "raise":
        t = time.time()
        raise_limit(st, args.raised_value)
        done("limit_raise_with_restart", time.time() - t)
        api.set_budget(args.raised_value)
    elif left_raised:
        log("limit: an earlier run raised it and did not restore it; it is restored at the end of this run")
        api.set_budget(read_api_yaml_limit()[0])
    if args.stop_after == "limit":
        return 0

    t_import = time.time()
    t = time.time()
    have, groups = read_registry(api)
    done("read_target", time.time() - t)
    # F7 (rule 5): before writing anything, a registry that already holds agents must be a cut import of THIS bundle
    eq, _miss, wrong, foreign = cut_import_check(by_id, registry_keys())
    if wrong or foreign:
        run["result"] = "refused: the registry is not a cut import of this bundle"
        run["self_enrolled"] = {"name_or_key_differs": wrong, "not_in_bundle": foreign}
        st.save()
        log("REFUSE: the 5.0 registry holds agents that are not this bundle's (id, name and key compared): name or key differs "
            "for %s; not in the bundle: %s. They enrolled by themselves (listeners or the 4.x password reached them). Nothing "
            "was imported; never import with --force over them. Decide per agent (remove it, then rerun)." % (wrong, foreign))
        return 3
    if eq:
        log("cut import: %d agent(s) already on 5.0, every one equal to the bundle by id, name and key; resuming" % len(eq))
    expected = load_expected(getattr(args, "expected_conf", None))
    tg, tc = do_groups(api, st, args.bundle, m, groups, refused, res, expected)
    done("groups_create", tg)
    done("groups_conf_and_policies", tc)
    log("groups: %s" % {k: v for k, v in res.items() if k.startswith(("group", "conf", "policy", "default"))})
    missing = [a for a in sorted(want) if a not in have]
    log("inserts: %d agents to insert, %d workers" % (len(missing), args.workers))
    done("inserts", do_inserts(api, st, by_id, missing, args.workers, res, args.cooldown_wait))
    log("inserts: %s (api %s)" % ({k: v for k, v in res.items() if k.startswith("insert")}, dict(api.stats)))
    if args.stop_after == "inserts":
        return 0
    t = time.time()
    have, _ = read_registry(api)
    plan = plan_memberships(want, {a: v["groups"] for a, v in have.items()})
    done("read_for_plan", time.time() - t)
    log("memberships: %d agents to change (%d reset)" % (len(plan), sum(1 for v in plan.values() if v[1])))
    done("memberships", do_memberships(api, st, want, plan, args.chunk, res))
    done("import_total", time.time() - t_import)

    # repair until equal
    t = time.time()
    passes = []
    for n in range(1, args.max_passes + 1):
        d, have, groups = compare(api, args.bundle, m, want, by_id, refused, expected)
        passes.append(summary(d))
        log("verify pass %d: %s" % (n, summary(d)))
        if not repairable(d):
            break
        do_groups(api, st, args.bundle, m, groups, refused, res, expected)
        if d["agents_missing"]:
            do_inserts(api, st, by_id, d["agents_missing"], 1, res, args.cooldown_wait)
            have, _ = read_registry(api)
        safe = {a: w for a, w in want.items() if a not in d["keys_differ"] and a not in d["renamed"]}   # F7: never an impostor's groups
        do_memberships(api, st, safe, plan_memberships(safe, {a: v["groups"] for a, v in have.items()}), args.chunk, res)
    run["verify_passes"] = passes
    done("verify_and_repair", time.time() - t)
    if args.stop_after == "repair":
        return 0

    # secrets, the limit back, one clean restart for all of them
    t = time.time()
    secrets = {}
    if args.with_password and os.path.isfile(os.path.join(args.bundle, "authd.pass")):
        secrets["authd.pass"] = install_secret(st, args.bundle, "authd.pass")
    if args.with_rbac and os.path.isfile(os.path.join(args.bundle, "rbac.db")):
        secrets["rbac.db"] = install_secret(st, args.bundle, "rbac.db")
    restored = put_back_yaml(st)
    run["secrets"] = secrets
    done("secrets_and_limit_files", time.time() - t)
    t = time.time()
    # E3 fold (E3-deb N1): a run that wrote nothing since the last restart (a repair that found the target equal, a
    # rerun after the gate) does not restart: a restart drops every connected agent and throws away a vulnerability
    # feed load in progress (E3-cluster: three identity-stage restarts discarded 8,400 to 93,300 documents each)
    pending = st.data.get("restart_pending")
    limit_pending = restored or (st.data.get("limit") or {}).get("state") == "restored-pending-restart"
    if pending or limit_pending:
        restart_manager(st, "apply %s%s" % (",".join(k for k, v in secrets.items() if v == "installed") or pending or "nothing",
                                             " and the original API limit" if limit_pending else ""))
    else:
        st.journal(action="restart_skipped", why="nothing written since the last restart")
        log("manager restart skipped: this run wrote nothing since the last restart (no secret, group, file, agent, "
            "membership or API limit), so the connected agents are not dropped")
    if os.path.isfile(st.saved_yaml):
        st.data["limit"]["state"] = "restored"
        st.data["limit"]["restored_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        st.save()
    done("restart", time.time() - t)
    if "rbac.db" in secrets:
        done("service_passwords_reset", reset_service_passwords(st))
    limit_now, _ = read_api_yaml_limit()
    api = Api(limit_now)        # the restored limit paces the rest; a fresh login with the published password

    # the same comparison after the clean restart
    t = time.time()
    after = []
    for n in range(1, args.max_passes + 1):
        d, have, groups = compare(api, args.bundle, m, want, by_id, refused, expected)
        after.append(summary(d))
        log("after restart, pass %d: %s" % (n, summary(d)))
        if not repairable(d):
            break
        do_groups(api, st, args.bundle, m, groups, refused, res, expected)
        if d["agents_missing"]:
            do_inserts(api, st, by_id, d["agents_missing"], 1, res, args.cooldown_wait)
            have, _ = read_registry(api)
        safe = {a: w for a, w in want.items() if a not in d["keys_differ"] and a not in d["renamed"]}   # F7
        do_memberships(api, st, safe, plan_memberships(safe, {a: v["groups"] for a, v in have.items()}), args.chunk, res)
    run["after_restart_passes"] = after
    done("verify_after_restart", time.time() - t)

    # gate
    yaml_ok = True
    if os.path.isfile(st.saved_yaml):
        yaml_ok = open(st.saved_yaml, "rb").read() == open(API_YAML, "rb").read()
    equal = not repairable(d) and not d["renamed"] and not d["keys_differ"] and not d["agents_extra"]
    run["gate"] = {"target_equals_bundle": equal, "set_aside": sorted(refused),
                   "api_yaml_is_the_original": yaml_ok, "api_limit_now": limit_now,
                   "differences": summary(d)}
    run["counters"] = dict(res)
    run["api_stats_last_client"] = dict(api.stats)
    run["total_s"] = round(time.time() - T0, 1)
    run["result"] = "PASS" if equal and yaml_ok else "FAIL"
    st.save()
    log("GATE %s: target equals the bundle %s (set aside: %s), api.yaml is the original %s, limit now %s/min; "
        "total %.0fs; timings %s; counters %s" % (run["result"], equal, sorted(refused) or "none", yaml_ok, limit_now,
                                                  time.time() - T0, json.dumps(tm), dict(res)))
    return 0 if run["result"] == "PASS" else 1


def cmd_verify(args):
    m, want, by_id = load_bundle(args.bundle)
    st = State(args.state) if args.state else None
    refused = set(((st.data.get("preflight") or {}).get("conf_refused") or {}) if st else {})
    api = Api(read_api_yaml_limit()[0])
    d, have, groups = compare(api, args.bundle, m, want, by_id, refused, load_expected(getattr(args, "expected_conf", None)))
    print(json.dumps({"summary": summary(d), "first": {k: v[:5] for k, v in d.items()}, "set_aside": sorted(refused),
                      "api_stats": dict(api.stats), "seconds": round(time.time() - T0, 1)}, indent=1))
    return 0 if not repairable(d) and not d["renamed"] and not d["keys_differ"] and not d["agents_extra"] else 1


def cmd_restore_limit(args):
    st = State(args.state)
    if put_back_yaml(st) or (st.data.get("limit") or {}).get("state") == "restored-pending-restart":
        restart_manager(st, "restore the original API limit")
        st.data["limit"]["state"] = "restored"
        st.save()
        log("limit: the original api.yaml is back and the manager restarted")
    else:
        log("limit: api.yaml is already the original (or was never changed)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("preflight", "run", "verify"):
        p = sub.add_parser(name)
        p.add_argument("bundle")
        p.add_argument("--state")
        p.add_argument("--with-password", action="store_true")
        p.add_argument("--with-rbac", action="store_true")
        p.add_argument("--expected-conf", help="settings/groups-pre/uploaded.json: agent.conf files the flow's pre-upgrade pass uploaded (E2 fold)")
        if name == "run":
            p.add_argument("--limit-mode", choices=("stock", "raise"), default="stock")
            p.add_argument("--raised-value", type=int, default=0, help="max_request_per_minute while raised (0 = off)")
            p.add_argument("--workers", type=int, default=1)
            p.add_argument("--chunk", type=int, default=500)
            p.add_argument("--max-passes", type=int, default=3)
            p.add_argument("--cooldown-wait", type=int, default=1200)
            p.add_argument("--stop-after", choices=("limit", "inserts", "repair"))
    p = sub.add_parser("restore-limit")
    p.add_argument("--state", required=True)
    args = ap.parse_args()
    if args.cmd == "run" and not args.state:
        ap.error("run needs --state")
    return {"preflight": cmd_preflight, "run": cmd_run, "verify": cmd_verify, "restore-limit": cmd_restore_limit}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
