#!/usr/bin/env python3
"""H5 copy of RD2's M3 loader (M3 header follows). H5 additions, each marked "H5:":
  * a retention journal (<state dir>/journal.json): per month its expiry (newest day + retention), whether it was
    skipped as already expired, loaded (with the count of every target index per source index) or deleted later by
    the retention. apply never creates or reloads a month the journal knows is expired; prove and on expect exactly
    what the retention should have left;
  * --retention takes d, h or m (minutes, lab), and --load-expired loads months already past it (the old behaviour);
  * remove-bundle (also on --remove-bundle): after a passing proof, delete the alert files and every other file that
    can hold alert content, keep what a rerun and the proof need, and say what is left;
  * --procs N: the Python shaping in N processes instead of threads (the GIL caps threads at one core);
  * rollback archives the load state and the journal, so a new apply starts clean.

M2 copy of H1's loader, using history-loader-map.json.

Bulk create, source mapping merge, proof, aliases, retention and rollback stay
with H1. Shaping runs in Python via loader_map.LoaderMapper before bulk create.
The ingest pipeline is empty; routing and registry groups are computed locally.
Use clean M2 targets/state: existing H1 documents are never overwritten.
Python 3.9+, standard library only; see README.md for offline validation limits.
"""
import argparse
import base64
from pathlib import Path
import calendar
import concurrent.futures
import fnmatch
import gzip
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from loader_map import LoaderMapper, MAP_SHA256

MAIN_PREFIX = "wazuh-legacy-4x-alerts-"
CLOUD_PREFIX = "wazuh-legacy-4x-cloud-"
ALIAS_MAIN = "wazuh-findings-v5-legacy-4x"
ALIAS_CLOUD = "wazuh-findings-v5-cloud-services-legacy-4x"
ALL = MAIN_PREFIX + "*," + CLOUD_PREFIX + "*"
TEMPLATE = PIPELINE = "wazuh-legacy-4x-history"
POLICY = "wazuh-legacy-4x-retention"
MARK = {"managed_by": "wazuh-migration-h1", "version": "0.3-m2", "field_map_sha256": MAP_SHA256}
DAY = re.compile(r"^(.*?)(\d{4})\.(\d{2})\.(\d{2})$")
FINDINGS = ["wazuh-findings-v5*", "wazuh-findings-v5-cloud-services*"]


def out(m=""):
    print(m, flush=True)


def must(res, what):
    s, o = res
    if s not in (200, 201):
        raise SystemExit("ERROR %s: HTTP %s %s" % (what, s, json.dumps(o)[:800]))
    return o


# ------------------------------------------------------------------------------------------ indexer access and shapes
FINDINGS_TEMPLATE = "wazuh-findings-v5-system-activity-template"
LENIENT = {"ip", "long", "date", "geo_point", "integer", "short", "double", "float"}   # types that get ignore_malformed


class Api:
    """The indexer's REST API over HTTPS (basic auth or a client certificate); retries a 429 (circuit breaker)."""
    def __init__(self, a):
        u = urllib.parse.urlsplit(a.url)
        self.host, self.port, self.addr = u.hostname, u.port or 9200, u.hostname
        for r in a.resolve or []:
            h, p, ad = r.split(":", 2)
            if h == self.host and int(p) == self.port: self.addr = ad
        self.ctx = ssl.create_default_context(cafile=a.cacert)
        if a.cert: self.ctx.load_cert_chain(a.cert, a.key)
        pw = a.password or os.environ.get("INDEXER_PASSWORD", "")
        self.auth = None if a.cert else "Basic " + base64.b64encode(f"{a.user}:{pw}".encode()).decode()

    def __call__(self, method, path, body=None, timeout=600):
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        h = {"Content-Type": "application/json"}
        if self.auth: h["Authorization"] = self.auth
        for attempt in range(8):
            sock = socket.create_connection((self.addr, self.port), timeout=timeout)
            conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=timeout)
            conn.sock = self.ctx.wrap_socket(sock, server_hostname=self.host)
            try:
                conn.request(method, path, body=data, headers=h)
                r = conn.getresponse(); b = r.read()
            finally:
                conn.close()
            if r.status == 429:            # circuit breaker on a 1 GB heap: wait and retry
                time.sleep(3 + 3 * attempt); continue
            try: return r.status, json.loads(b or b"{}")
            except ValueError: return r.status, b.decode(errors="replace")
        return 429, {"error": "still 429 after retries"}


def wcs_types(api):
    """Every leaf field of the installed findings template with its mapping, and the template's index settings."""
    t = must(api("GET", f"/_index_template/{FINDINGS_TEMPLATE}"), "read the findings template")
    it = t["index_templates"][0]["index_template"]["template"]
    m = it["mappings"]; types = {}
    for d in m.get("dynamic_templates", []):
        (_, b), = d.items()
        if "path_match" in b: types[b["path_match"]] = dict(b["mapping"])
    def leaves(p, pre=""):
        for k, v in p.items():
            if "properties" in v: yield from leaves(v["properties"], pre + k + ".")
            elif "type" in v and v["type"] != "object": yield pre + k, v
    for k, v in leaves(m.get("properties", {})): types.setdefault(k, dict(v))
    return types, it["settings"]["index"]


def put_path(props, dotted, leaf):
    parts = dotted.split(".")
    for p in parts[:-1]: props = props.setdefault(p, {"properties": {}})["properties"]
    props[parts[-1]] = leaf


def policy_body(a):
    # No ism_template: the indices carry the data date as creation date, and ISM only auto-attaches newer indices.
    return {"policy": {"description": f"migrated 4.x alerts are deleted {a.retention} after the newest day they hold "
                                      "(index.creation_date is the data date).",
                       "default_state": "keep",
                       "states": [{"name": "keep", "actions": [],
                                   "transitions": [{"state_name": "delete", "conditions": {"min_index_age": a.retention}}]},
                                  {"name": "delete", "actions": [{"delete": {}}], "transitions": []}]}}


def detect_cluster(api):
    """The cluster name the live 5.0 documents carry (wazuh.cluster.name), or None."""
    s, o = api("POST", "/wazuh-findings-v5*,wazuh-events-v5*/_search",
               {"size": 0, "query": {"bool": {"must_not": [{"term": {"tags": "v4-legacy"}}]}},
                "aggs": {"c": {"terms": {"field": "wazuh.cluster.name", "size": 5}}}})
    b = o.get("aggregations", {}).get("c", {}).get("buckets", []) if s == 200 else []
    return b[0]["key"] if b else None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def write_json(path, obj):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)


# ------------------------------------------------------------------------------------------- bundle
class Bundle:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.man = json.load(open(os.path.join(self.path, "manifest.json")))
        self.months = {}          # "YYYY.MM" -> {"srcs": [index...], "docs": n, "cd": epoch ms of the newest day}
        self.skipped = []
        for n, ent in sorted(self.man["indices"].items()):
            m = DAY.match(n)
            if not m or "alerts" not in m.group(1):
                self.skipped.append(n)
                continue
            _, y, mo, d = m.groups()
            e = self.months.setdefault("%s.%s" % (y, mo), {"srcs": [], "docs": 0, "cd": 0})
            e["srcs"].append(n)
            e["docs"] += ent["docs_expected"]
            e["cd"] = max(e["cd"], calendar.timegm((int(y), int(mo), int(d), 23, 59, 59)) * 1000)

    def month_of(self, index):
        m = DAY.match(index)
        return "%s.%s" % (m.group(2), m.group(3))

    def ent(self, index):
        return json.load(open(os.path.join(self.path, "indices", index + ".json")))

    def verify(self, allow_incomplete=False, only=None):
        bad, n = [], 0
        for name, ent in self.man["indices"].items():
            if only is not None and name not in only:      # files of months that will not be loaded are not read
                continue
            if not ent["complete"] and not allow_incomplete:
                bad.append("%s: dumped while still being written (take the final delta after the write stop)" % name)
            for f in ent["files"]:
                p = os.path.join(self.path, f["file"])
                n += 1
                if not os.path.exists(p):
                    bad.append("missing: " + f["file"])
                elif os.path.getsize(p) != f["bytes"] or sha256_file(p) != f["sha256"]:
                    bad.append("corrupt or truncated: " + f["file"])
        return n, bad

    def total(self):
        return sum(x["docs"] for x in self.months.values())


# ------------------------------------------------------------------------------- retention journal
def retention_ms(r):
    m = re.match(r"^(\d+)([dhm])$", r or "")
    if not m:
        raise SystemExit("ERROR --retention must be a number of days, hours or minutes (30d, 12h, 90m): %r" % r)
    return int(m.group(1)) * {"d": 86400000, "h": 3600000, "m": 60000}[m.group(2)]


def iso(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000.0))


def state_dir(a, b):
    return a.state_dir or os.path.join(b.path, "load-state")


class Journal:
    """What the tool knows about every month, so that a rerun after the retention acted neither reloads nor
    re-creates what the retention deleted, and the proof expects exactly what should be there.
    month status: expired-before-load | loading | loaded   (+ "deleted_by_retention": {index: first seen absent})"""

    def __init__(self, path):
        self.path = path
        self.d = json.load(open(path)) if os.path.exists(path) else {"months": {}}

    def save(self):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        write_json(self.path, self.d)

    def month(self, k):
        return self.d["months"].setdefault(k, {})


def target_present(api):
    return {t["index"]: int(t["docs.count"] or 0) for t in existing_targets(api)}


def per_source_counts(api, index):
    """{source index: documents} in one target index (terms on legacy.index)."""
    s, o = api("POST", "/%s/_search" % index, {"size": 0, "aggs": {"i": {"terms": {"field": "legacy.index", "size": 20000}}}})
    if s != 200:
        raise SystemExit("ERROR counting %s per source index: HTTP %s %s" % (index, s, json.dumps(o)[:300]))
    return {x["key"]: x["doc_count"] for x in o["aggregations"]["i"]["buckets"]}


def classify_months(api, a, b, j, now_ms, quiet=False):
    """Decide, per month, what this run does with it. Returns (load, expired, loaded) lists of month keys.
    Also records retention deletions of loaded months, and refuses a loaded month that vanished before its date."""
    ret = retention_ms(a.retention)
    present = target_present(api)
    load, expired, loaded, fails = [], [], [], []
    for k, x in sorted(b.months.items()):
        e = j.month(k)
        exp = x["cd"] + ret
        if e.get("status") == "loaded":
            loaded.append(k)
            for t in sorted(e.get("targets", {})):
                if t in present:
                    continue
                if now_ms >= e["expires_ms"]:
                    if t not in e.setdefault("deleted_by_retention", {}):
                        e["deleted_by_retention"][t] = iso(now_ms)
                        if not quiet:
                            out("  %s: %s deleted by the retention (expired %s): expected, not re-created" % (k, t, iso(e["expires_ms"])))
                else:
                    fails.append("%s: %s is missing but its retention date is %s: something other than the retention deleted it" % (
                        k, t, iso(e["expires_ms"])))
        elif e.get("status") == "expired-before-load" and not a.load_expired and now_ms >= exp:
            expired.append(k)
        elif now_ms >= exp and not a.load_expired:
            expired.append(k)
            e.update({"status": "expired-before-load", "expires_ms": exp, "docs": x["docs"], "decided": iso(now_ms)})
        else:
            load.append(k)
            if e.get("status") == "expired-before-load":   # --load-expired, or a longer retention on this rerun
                e.clear()
    j.save()
    if fails:
        for f in fails:
            out("  REFUSE " + f)
        raise SystemExit("ERROR a loaded month is missing before its retention date; find out why, then roll back and load again")
    return load, expired, loaded


# ------------------------------------------------------------------------------------------ template
def build_template(api, b, priority, agent_ids, registry=None):
    """WCS field types from the installed findings template; the 4.x mapping (from the bundle) under legacy.alert."""
    types, fset = wcs_types(api)
    copy = {}  # compatibility argument; LoaderMapper owns all shaping
    copy["message"] = "full_log"        # S3's free-text fix (native findings carry the log line in message)
    if not agent_ids:
        copy.pop("wazuh.agent.id", None)
    wanted = LoaderMapper().targets()
    if not agent_ids:
        wanted.discard("wazuh.agent.id")
    if not registry:
        wanted.discard("wazuh.agent.groups")
    if registry:
        wanted.add("wazuh.agent.groups")   # group stamp
    missing = sorted(w for w in wanted if w not in types)
    if missing:
        raise SystemExit("ERROR: not in the installed findings schema (the shape map is for another build): %s" % missing)
    expected = LoaderMapper().spec['target_schema']
    drift = [w for w in wanted if w in expected and types[w].get('type') != expected[w]['type']]
    if drift:
        raise SystemExit("ERROR: installed findings types differ from the tested map: %s" % sorted(drift))
    props = {}
    for w in sorted(wanted):
        leaf = dict(types[w])
        if leaf.get("type") in LENIENT:
            leaf["ignore_malformed"] = True
        put_path(props, w, leaf)
    old, extra, df4 = {}, {}, []
    conflicts = []
    for month in b.months.values():
        for idx in month["srcs"]:
            ent = b.ent(idx)
            m = ent["mappings"]
            merge_checked(old, m.get("properties", {}), "legacy.alert", conflicts)
            for k in ("dynamic_templates", "date_detection", "numeric_detection"):
                if k in m and k not in extra:
                    extra[k] = m[k]
            for f in ent["settings"]["index"].get("query", {}).get("default_field", []):
                if f not in df4:
                    df4.append(f)
    for c in sorted(set(conflicts)):
        out("  mapping: 4.x daily indices disagree on %s" % c)
    props["legacy"] = {"properties": {"index": {"type": "keyword"}, "id": {"type": "keyword"}, "alert": {"properties": old}}}
    df = list(fset.get("query", {}).get("default_field", [])) + ["legacy.alert." + f for f in df4]
    settings = {"index.number_of_shards": 1, "index.auto_expand_replicas": fset.get("auto_expand_replicas", "0-1"),
                "index.codec": fset.get("codec", "default"),
                "index.max_docvalue_fields_search": int(fset.get("max_docvalue_fields_search", 200)),
                "index.mapping.total_fields.limit": 10000, "index.query.default_field": df[:1000]}
    mappings = dict(extra)
    mappings.update({"dynamic": "true", "properties": props, "_meta": dict(MARK, wazuh_migration_bundle=b.man["bundle_id"])})
    body = {"index_patterns": [MAIN_PREFIX + "*", CLOUD_PREFIX + "*"], "priority": priority, "_meta": dict(MARK),
            "template": {"settings": settings, "mappings": mappings}}
    return body, len(wanted), copy


def merge_checked(dst, src, path, conflicts):
    """Merge the mappings of the daily 4.x indices that end in one monthly index. 4.x maps data.* dynamically per day,
    so the same field can be a number one day and a keyword another. Where they disagree the field becomes a keyword
    (it accepts both; _source is untouched), or an unindexed object when one day has an object and another a value."""
    for k, v in src.items():
        if k not in dst:
            dst[k] = json.loads(json.dumps(v))
        elif "properties" in dst[k] and "properties" in v:
            merge_checked(dst[k]["properties"], v["properties"], path + "." + k, conflicts)
        elif ("properties" in dst[k]) != ("properties" in v) or dst[k].get("enabled") is False:
            if dst[k].get("enabled") is not False:
                conflicts.append("%s.%s: object one day, %s another -> kept in _source, not indexed" % (path, k, (v if "properties" in dst[k] else dst[k]).get("type")))
            dst[k] = {"type": "object", "enabled": False}
        elif dst[k].get("type") != v.get("type"):
            if dst[k].get("type") != "keyword" or "widened_by_migration" not in dst[k].get("meta", {}):
                conflicts.append("%s.%s: %s one day, %s another -> keyword" % (path, k, dst[k].get("type"), v.get("type")))
            dst[k] = {"type": "keyword", "meta": {"widened_by_migration": "true"}}


def pipeline_body(cluster, copy, registry=None):
    """Never reapply H1's FIRST tables to the Python-shaped document."""
    return {"description": "M2: schema-checked Python conversion using history-loader-map.json", "processors": []}


# -------------------------------------------------------------------------------------------- checks
def count(api, idx, q=None):
    s, o = api("POST", "/%s/_count?ignore_unavailable=true&allow_no_indices=true" % idx, {"query": q or {"match_all": {}}})
    if s == 403:   # a refused count read as -1 documents; say which permission is missing
        raise SystemExit("ERROR count %s: HTTP 403 %s" % (idx, json.dumps(o)[:600]))
    return o.get("count", -1) if s == 200 else -1


def existing_targets(api):
    s, o = api("GET", "/_cat/indices/%s?format=json&h=index,docs.count,status&expand_wildcards=all&s=index" % ALL)
    if s != 200 or not isinstance(o, list):   # strict; [] on a refusal hid existing indices from every check
        raise SystemExit("ERROR list the history indices: HTTP %s %s" % (s, json.dumps(o)[:600]))
    return o


def precheck(api, b, a):
    """Refuse before writing anything. Returns the cluster name to stamp."""
    fails = []
    h = must(api("GET", "/_cluster/health"), "cluster health")
    if h["status"] == "red":
        fails.append("cluster status is red")
    # a gate that cannot read its input refuses; with a restricted user H1/M3 silently used defaults here
    cs = must(api("GET", "/_cluster/settings?include_defaults=true&flat_settings=true&filter_path=**.cluster.max_shards_per_node"), "read the shard limit")
    merged = {}
    for k in ("defaults", "persistent", "transient"):
        merged.update((cs or {}).get(k, {}))
    limit = int(next(iter(merged.values()), 1000)) * max(h.get("number_of_data_nodes", 1), 1)
    have = h["active_shards"] + h["unassigned_shards"] + h["initializing_shards"]
    new = 2 * len(b.months)
    out("shards: %d now, the history adds at most %d, limit %d" % (have, new, limit))
    if have + new > limit:
        fails.append("%d + %d shards exceed the limit %d" % (have, new, limit))
    fs = must(api("GET", "/_nodes/stats/fs?filter_path=nodes.*.fs.total"), "read the free disk of the data nodes")   # strict
    free = min((n["fs"]["total"].get("available_in_bytes", 0) for n in (fs or {}).get("nodes", {}).values()), default=0)
    raw = sum(f.get("raw_bytes", 0) for e in b.man["indices"].values() for f in e["files"])
    out("disk: %.1f MB free on the data path, the alerts are %.1f MB uncompressed" % (free / 1048576.0, raw / 1048576.0))
    if free and free < 3 * raw:
        fails.append("less than three times the uncompressed size of the alerts is free on the indexer data path")
    for t in existing_targets(api):
        cur = must(api("GET", "/%s/_mapping?filter_path=*.mappings._meta" % t["index"]), "read the mapping of %s" % t["index"])   # strict
        if (cur or {}).get(t["index"], {}).get("mappings", {}).get("_meta", {}).get("wazuh_migration_bundle") != b.man["bundle_id"]:
            fails.append("index %s exists and was not created from this bundle" % t["index"])
        if (cur or {}).get(t["index"], {}).get("mappings", {}).get("_meta", {}).get("field_map_sha256") != MAP_SHA256:
            fails.append("index %s uses another field map; reload into clean M2 targets" % t["index"])
    for alias in (ALIAS_MAIN, ALIAS_CLOUD):
        s, o = api("GET", "/_data_stream/%s" % alias)
        if s == 200 and o.get("data_streams"):
            fails.append("a data stream is already named %s" % alias)
        if api("HEAD", "/%s" % alias)[0] == 200:
            s, o = api("GET", "/_alias/%s" % alias)
            if s != 200:
                fails.append("an index is already named %s" % alias)
    cluster = a.cluster_name or detect_cluster(api)
    if not cluster:
        fails.append("cannot tell the 5.0 cluster name (no native document yet): pass --cluster-name")
    if b.skipped:
        out("not alert indices, left in the bundle and not loaded: %s" % ", ".join(b.skipped[:6]))
    if fails:
        for f in fails:
            out("  REFUSE " + f)
        raise SystemExit(2)
    return cluster


# ---------------------------------------------------------------------------------------------- load
class State:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()
        self.d = json.loads(open_state.read_text()) if (open_state := Path(path)).exists() else {"files": {}}
        if self.d.get("files") and self.d.get("field_map_sha256") != MAP_SHA256:
            raise RuntimeError("Load state uses another field map; use clean M2 targets and state")
        self.d["field_map_sha256"] = MAP_SHA256

    def done(self, name, stats):
        with self.lock:
            self.d["files"][name] = stats
            write_json(self.path, self.d)


# the loader runs beside live traffic after the opening, and F10 saw the indexer's parent breaker
# at 98 to 99.6 % of its limit during the load: a trip refuses live events too. So the loader reads the parent breaker
# before it sends, waits while any node is above --breaker-max, and treats a breaker refusal (429, 503,
# circuit_breaking_exception, es_rejected_execution_exception) as a reason to back off and send again, never as a failure,
# until --breaker-wait-max seconds have passed without one batch getting through.
SLEEP = time.sleep           # tests replace these two
CLOCK = time.monotonic
BACKOFF_TYPES = ("circuit_breaking_exception", "es_rejected_execution_exception")
# an indexer restart during the load refused the connection; the guard's breaker read let the
# ConnectionRefusedError through and the load ended with a traceback. A connection refused, reset or timed out, or a
# broken HTTP answer, means "the indexer is not ready": the load waits and tries again, with the same stop time as a
# breaker that stays high (--breaker-wait-max), then stops resumable.
NOT_READY = (OSError, http.client.HTTPException)


def _refusal_type(r):
    """The error type of a whole-request refusal body, if it is one of the breaker's."""
    if isinstance(r, dict):
        e = r.get("error")
        t = (e.get("type") or (e.get("root_cause") or [{}])[0].get("type")) if isinstance(e, dict) else str(e or "")
        return t if any(x in str(t) for x in BACKOFF_TYPES) else None
    return None


class Breaker:
    def __init__(self, api, limit=0.85, every_s=5.0, wait_max_s=1800.0):
        self.api, self.limit, self.every_s, self.wait_max_s = api, limit, every_s, wait_max_s
        self.last, self.unreadable_said = None, False
        self.paused_s = 0.0

    def ratio(self):
        """(highest parent-breaker use over the nodes as a fraction of its limit, node), or (None, why) unreadable."""
        s, r = self.api("GET", "/_nodes/stats/breaker?filter_path=nodes.*.name,nodes.*.breakers.parent", timeout=30)
        if s != 200 or not isinstance(r, dict):
            return None, "HTTP %s" % s
        best = (None, None)
        for nid, n in (r.get("nodes") or {}).items():
            p = (n.get("breakers") or {}).get("parent") or {}
            lim, est = p.get("limit_size_in_bytes"), p.get("estimated_size_in_bytes")
            if lim:
                x = float(est or 0) / float(lim)
                if best[0] is None or x > best[0]:
                    best = (x, n.get("name") or nid)
        return best if best[0] is not None else (None, "no parent breaker in the answer")

    def wait(self, stats=None):
        """Before a batch: wait while the parent breaker is above the limit (read at most every every_s seconds)."""
        if self.limit <= 0:
            return
        now = CLOCK()
        if self.last is not None and now - self.last < self.every_s:
            return
        self.last = now
        t0, delay = now, 2.0
        while True:
            try:
                x, node = self.ratio()
            except NOT_READY as e:
                not_ready(e, t0, delay, self.wait_max_s, stats)
                delay = min(delay * 2, 60)
                self.last = CLOCK()
                continue
            DOWN.answered(CLOCK())
            if x is None:
                if not self.unreadable_said:      # a user without cluster monitor rights: the load goes on, the retry below still holds
                    out("  breaker: cannot read _nodes/stats/breaker (%s): the load goes on, backing off only on refusals" % node)
                    self.unreadable_said = True
                return
            if x < self.limit:
                return
            if CLOCK() - t0 > self.wait_max_s:
                raise RuntimeError("the indexer's parent breaker stayed at %.1f %% of its limit on %s for %d s: the load stops "
                                   "here and resumes with the same command" % (100 * x, node, self.wait_max_s))
            out("  breaker: parent at %.1f %% of its limit on %s (above %.0f %%): pausing the load %.0f s so live events keep "
                "their headroom" % (100 * x, node, 100 * self.limit, delay))
            if stats is not None:
                stats["paused_s"] = stats.get("paused_s", 0) + delay
            SLEEP(delay)
            delay = min(delay * 2, 60)
            self.last = CLOCK()


class Down:
    """E4-deb N-F2a and N-F2b: one record, for the whole load, of since when the indexer has not answered. Every thread
    and every process of the load reads the same start, so the stop at --breaker-wait-max comes once that long has
    passed since the indexer stopped answering (before, each process and each file queued behind it timed its own wait:
    184 s for a 60 s setting, about 1.5 h at the default), and the summary reports the wall-clock time the indexer did
    not answer, not the sum of the processes' waits (132 s reported for an 18 s restart). Shared memory when the load
    runs in processes (created before the fork), plain values otherwise."""

    def __init__(self, shared=False):
        if shared:
            import multiprocessing
            self._start, self._total = multiprocessing.Value("d", -1.0), multiprocessing.Value("d", 0.0)
            self._lock = self._start.get_lock()
        else:
            self._start, self._total = _Box(-1.0), _Box(0.0)
            self._lock = threading.Lock()

    def since(self, now):
        """The start of the current outage (recorded now if none is running)."""
        with self._lock:
            if self._start.value < 0:
                self._start.value = now
            return self._start.value

    def answered(self, now):
        """A request was answered: an outage in progress ends and its wall-clock length is added once."""
        with self._lock:
            if self._start.value >= 0:
                self._total.value += max(0.0, now - self._start.value)
                self._start.value = -1.0

    def total(self):
        return self._total.value


class _Box:
    def __init__(self, v):
        self.value = v


DOWN = Down()


def not_ready(e, t0, delay, wait_max_s, stats):
    """E3-deb N6: the indexer did not answer (restarting): pause, or stop resumable once wait_max_s has passed since the
    indexer stopped answering for the whole load (DOWN; t0 kept for the callers' own first failure)."""
    start = DOWN.since(CLOCK())
    if CLOCK() - start > wait_max_s:
        raise RuntimeError("the indexer did not answer for %d s (%s: %s): the load stops here and resumes with the same "
                           "command" % (wait_max_s, type(e).__name__, e))
    out("  indexer not ready (%s: %s): it may be restarting; pausing the load %.0f s" % (type(e).__name__, e, delay))
    if stats is not None:
        stats["not_ready_s"] = stats.get("not_ready_s", 0) + delay
    SLEEP(delay)


def bulk(api, index, pairs, stats, rejected, breaker=None):
    path = "/%s/_bulk?pipeline=%s&filter_path=errors,items.*.status,items.*._index,items.*._id,items.*.error.type,items.*.error.reason" % (
        index, urllib.parse.quote(PIPELINE))
    delay = 1.0
    t_ok = CLOCK()
    wait_max = breaker.wait_max_s if breaker else 1800.0
    while pairs:
        if breaker:
            breaker.wait(stats)
        body = b"".join(x + y for x, y in pairs)
        try:
            s, r = api("POST", path, body, timeout=600)
        except NOT_READY as e:      # E3-deb N6: sent again once it answers; documents carry their ids (409 = already there)
            not_ready(e, t_ok, delay, wait_max, stats)
            delay = min(delay * 2, 60)
            continue
        DOWN.answered(CLOCK())
        if s in (429, 503) or (s != 200 and _refusal_type(r)):
            # the whole batch refused by a breaker or a full queue: back off and send it again
            if CLOCK() - t_ok > wait_max:
                raise RuntimeError("bulk to %s: refused for %d s (HTTP %s %s): the load stops here and resumes with the same command" % (
                    index, wait_max, s, json.dumps(r)[:300]))
            stats["refused_batches"] = stats.get("refused_batches", 0) + 1
            out("  breaker: bulk to %s refused (HTTP %s %s): backing off %.0f s" % (index, s, _refusal_type(r) or "", delay))
            SLEEP(delay)
            delay = min(delay * 2, 60)
            continue
        if s != 200:
            raise RuntimeError("bulk to %s: HTTP %s %s" % (index, s, json.dumps(r)[:600]))
        retry = []
        for pair, item in zip(pairs, r.get("items", [])):
            it = item.get("create") or item.get("index") or {}
            st = it.get("status", 500)
            if st in (200, 201):
                stats["created"] += 1
                if str(it.get("_index", "")).startswith(CLOUD_PREFIX):
                    stats["cloud"] += 1
            elif st == 409:
                stats["existing"] += 1
            elif st in (429, 503) or (it.get("error") or {}).get("type") in BACKOFF_TYPES:
                retry.append(pair)
            else:
                stats["rejected"] += 1
                err = it.get("error", {})
                with rejected["lock"]:
                    rejected["f"].write(json.dumps({"index": index, "id": it.get("_id"), "status": st, "type": err.get("type"),
                                                    "reason": str(err.get("reason"))[:400]}) + "\n")
                    rejected["f"].flush()
        if len(retry) < len(pairs):
            t_ok = CLOCK()
        elif CLOCK() - t_ok > wait_max:
            raise RuntimeError("bulk to %s: every document refused for %d s: the load stops here and resumes with the same command" % (index, wait_max))
        pairs = retry
        if retry:
            stats["retried"] += len(retry)
            SLEEP(delay)
            delay = min(delay * 2, 20)


def _docs_of_file(b, f):
    """(meta, source) pairs of one dump file: a metadata line ({"_id", "_routing"?}) then the document."""
    with gzip.open(os.path.join(b.path, f["file"]), "rb") as fh:
        while True:
            m = fh.readline()
            if not m:
                break
            s = fh.readline()
            if not s:
                raise RuntimeError("%s: odd number of lines (truncated)" % f["file"])
            yield json.loads(m), json.loads(s)


def _docs_of_index(api, index, page):
    """OF1 (decision 9): (meta, source) pairs of an index on the target indexer itself: the snapshot transport's
    restored 4.x daily copy, read with a scroll in _doc order, so it goes through the same Python shaping as a dump."""
    s, r = api("POST", "/%s/_search?scroll=10m" % urllib.parse.quote(index), {"size": page, "sort": ["_doc"]}, timeout=600)
    if s != 200:
        raise RuntimeError("read %s: HTTP %s %s" % (index, s, json.dumps(r)[:400]))
    sid = r.get("_scroll_id")
    try:
        while True:
            hits = (r.get("hits") or {}).get("hits") or []
            if not hits:
                break
            for h in hits:
                meta = {"_id": h["_id"]}
                if h.get("_routing") is not None:
                    meta["_routing"] = h["_routing"]
                yield meta, h["_source"]
            s, r = api("POST", "/_search/scroll", {"scroll": "10m", "scroll_id": sid}, timeout=600)
            if s != 200:
                raise RuntimeError("read %s (scroll): HTTP %s %s" % (index, s, json.dumps(r)[:400]))
            sid = r.get("_scroll_id") or sid
    finally:
        if sid:
            api("DELETE", "/_search/scroll", {"scroll_id": [sid]}, timeout=60)


def shape_and_send(a, b, src, docs, api, rejected):
    """Shape every (meta, source) of one 4.x source index in Python (the corrected field map) and bulk-create it into
    its month's targets. Shared by the dump-and-load transport (load_file) and the snapshot transport (load_index)."""
    brk = Breaker(api, getattr(a, "breaker_max", 0.85), wait_max_s=getattr(a, "breaker_wait_max", 1800))   # OF1 (decision 10)
    target = MAIN_PREFIX + b.month_of(src)
    stats = {"docs": 0, "created": 0, "existing": 0, "retried": 0, "rejected": 0, "cloud": 0}
    converter = LoaderMapper(a.cluster_name, a.agent_ids == "carried", load_registry(a))
    pairs, nbytes = [], 0
    for meta, source in docs:
        doc = converter.convert(source, src, meta["_id"])
        cloud = doc.get("wazuh", {}).get("integration", {}).get("category") == "cloud-services"
        act = {"_id": src + ":" + meta["_id"],
               "_index": (CLOUD_PREFIX if cloud else MAIN_PREFIX) + b.month_of(src)}
        if "_routing" in meta:
            act["routing"] = meta["_routing"]
        x = b'{"create":' + json.dumps(act).encode() + b"}\n"
        y = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        pairs.append((x, y))
        nbytes += len(x) + len(y)
        stats["docs"] += 1
        if len(pairs) >= a.bulk_docs or nbytes >= a.bulk_bytes:
            bulk(api, target, pairs, stats, rejected, brk)
            pairs, nbytes = [], 0
    if pairs:
        bulk(api, target, pairs, stats, rejected, brk)
    return stats


def load_file(a, b, f, state, rejected):
    api = Api(a)
    stats = shape_and_send(a, b, f["index"], _docs_of_file(b, f), api, rejected)
    if stats["docs"] != f["docs"]:
        raise RuntimeError("%s: %d documents read, manifest says %d" % (f["file"], stats["docs"], f["docs"]))
    if not stats["rejected"]:
        state.done(f["file"], stats)
    return stats


def load_index(a, b, src, rejected):
    """OF1 (decision 9): one restored 4.x daily index through the Python shaping; the count must equal the manifest's."""
    api = Api(a)
    stats = shape_and_send(a, b, src, _docs_of_index(api, src, a.bulk_docs), api, rejected)
    want = b.man["indices"][src]["docs_expected"]
    if stats["docs"] != want:
        raise RuntimeError("%s: %d documents read from the restored copy, the 4.x source had %d" % (src, stats["docs"], want))
    return src, stats


class _NoState:
    def done(self, name, stats):
        pass


def load_file_proc(a, b, f):
    """H5: load_file in a worker process (fork). The parent records the state and the rejected documents."""
    import io
    buf = io.StringIO()
    stats = load_file(a, b, f, _NoState(), {"lock": threading.Lock(), "f": buf})
    return stats, f["file"], buf.getvalue()


def load_index_proc(a, b, src):
    """PERF1: load_index in a worker process (fork), for the snapshot transport's --procs; the parent writes the rejected
    documents. The shaping is the same function in both modes, so the documents are the same."""
    import io
    buf = io.StringIO()
    src_, stats = load_index(a, b, src, {"lock": threading.Lock(), "f": buf})
    return src_, stats, buf.getvalue()


def report_sources(b, a):
    """H1: what the user must know before loading: indices created before OpenSearch 2.0 (copied: the dump reads them
    through search and the load re-creates them on 5.0) and months the retention deletes as soon as ISM runs."""
    by = {}
    for n, e in sorted(b.man["indices"].items()):
        if n in b.skipped:
            continue
        v = int(e.get("version_created", 0))
        major = v // 1000000 if v < 100000000 else (v ^ 0x08000000) // 1000000   # OpenSearch ids carry bit 27
        by.setdefault(major, []).append(n)
    for major, names in sorted(by.items()):
        out("source indices created by OpenSearch %s.x: %d%s" % (major, len(names), (" (" + ", ".join(names[:5]) + ")") if major < 2 else ""))
    if any(m < 2 for m in by):
        out("  NOTE indices created before OpenSearch 2.0 are copied by value: 5.0 cannot open or restore them, the dump reads them through search")
    # the months past the retention are decided by classify_months and reported by cmd_plan.


def cmd_plan(api, a, b, write_journal=False):
    """H5: the plan decides per month (journal) and verifies only the files it will load."""
    j = Journal(os.path.join(state_dir(a, b), "journal.json"))
    if j.d.get("bundle_data_removed"):
        out("bundle %s: its alert files were removed on %s after a passing proof; nothing can be loaded from it" % (
            b.man["bundle_id"], j.d["bundle_data_removed"]["at"]))
        return None, j, [], [], []
    now = time.time() * 1000
    if not write_journal:      # plan alone writes nothing, not even the journal
        j.save = lambda: None
    load, expired, loaded = classify_months(api, a, b, j, now)
    srcs = {s for k in load for s in b.months[k]["srcs"]}
    n, bad = b.verify(a.allow_incomplete, only=srcs)
    out("bundle %s: %d files verified, %d problem(s); %d 4.x indices, %d documents in the bundle, %d month(s)" % (
        b.man["bundle_id"], n, len(bad), sum(len(x["srcs"]) for x in b.months.values()), b.total(), len(b.months)))
    for x in bad[:20]:
        out("  " + x)
    if bad:
        raise SystemExit(2)
    cluster = precheck(api, b, a)
    out("wazuh.cluster.name for the history: %s" % cluster)
    report_sources(b, a)
    ret = retention_ms(a.retention)
    if expired:
        out("retention %s: %d month(s) already past it are NOT loaded (expired before the migration): %s (%d documents). "
            "To keep them, rerun with a longer --retention (or --load-expired, and the retention deletes them at its next runs)" % (
                a.retention, len(expired), ", ".join(expired), sum(b.months[k]["docs"] for k in expired)))
    soon = [k for k in load if b.months[k]["cd"] + ret < now + 86400000]
    if soon:
        out("retention %s: %s expire(s) within a day: loaded, then deleted by the retention at its first runs after that" % (
            a.retention, ", ".join("%s on %s" % (k, iso(b.months[k]["cd"] + ret)) for k in soon)))
    if load:
        out("retention %s: the oldest month to load goes on %s" % (a.retention, iso(min(b.months[k]["cd"] for k in load) + ret)))
    if loaded:
        out("already loaded by an earlier run (never reloaded): %s" % ", ".join(loaded))
    out("to load: %s (%d documents)" % (", ".join(load) or "nothing", sum(b.months[k]["docs"] for k in load)))
    out("plan: ok, nothing written" if not write_journal else "plan: ok")
    return cluster, j, load, expired, loaded


def load_registry(a):
    """H1: {agent id: {"name": ..., "groups": [...]}} from --agent-registry; only used when the ids were carried."""
    if not a.agent_registry:
        return None
    if a.agent_ids != "carried":
        out("group stamp skipped: the agent registry was not imported, so 4.x ids and groups mean nothing on 5.0")
        return None
    return json.load(open(a.agent_registry))["agents"]


def cmd_apply(api, a, b):
    T0 = time.time()
    sdir = state_dir(a, b)
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    cluster, j, load, expired, loaded = cmd_plan(api, a, b, write_journal=True)
    if cluster is None:     # the bundle's alerts were removed after the proof: only the proof can run
        return cmd_prove(api, a, b)
    a.cluster_name = cluster
    state = State(os.path.join(sdir, "state.json"))
    ret = retention_ms(a.retention)
    registry = load_registry(a)
    body, n, copy = build_template(api, b, a.priority, a.agent_ids == "carried", registry)
    must(api("PUT", "/_index_template/%s" % TEMPLATE, body), "PUT template")
    out("template %s: priority %d, %d 5.0 fields + legacy.* (4.x mapping from the bundle); wazuh.agent.id %s" % (
        TEMPLATE, a.priority, n, "filled (the agent registry was imported)" if a.agent_ids == "carried" else "NOT filled (registry not imported)"))
    must(api("PUT", "/_ingest/pipeline/%s" % PIPELINE, pipeline_body(cluster, copy, registry)), "PUT pipeline")
    if registry:
        out("group stamp: %d registry agent(s) with groups, matched on id and name: %s" % (
            sum(1 for e in registry.values() if e["groups"]), {k: e for k, e in sorted(registry.items()) if e["groups"]}))
    s, o = api("GET", "/_plugins/_ism/policies/%s" % POLICY)
    if s not in (200, 404):   # strict (a refused read became a 409 on the PUT)
        raise SystemExit("ERROR read the retention policy: HTTP %s %s" % (s, json.dumps(o)[:600]))
    q = "?if_seq_no=%s&if_primary_term=%s" % (o["_seq_no"], o["_primary_term"]) if s == 200 else ""
    pol = policy_body(a)
    pol["policy"]["description"] = "migrated 4.x alerts are deleted %s after the newest day they hold." % a.retention
    must(api("PUT", "/_plugins/_ism/policies/%s%s" % (POLICY, q), pol), "PUT policy")
    out("pipeline %s, retention policy %s (%s from the data date, no ism_template)" % (PIPELINE, POLICY, a.retention))
    present = target_present(api)
    for month in expired:     # partial targets of a month that expired before its load completed: never kept
        for dst in (MAIN_PREFIX + month, CLOUD_PREFIX + month):
            if dst in present:
                api("POST", "/_plugins/_ism/remove/%s" % dst)
                s, _ = api("DELETE", "/%s" % dst)
                out("  %s: deleted the partial %s (%s documents): the month is past the retention, its load never completed (HTTP %s)" % (
                    month, dst, present[dst], s))
    for month in load:        # only months to load are created or reopened; loaded and expired ones are never touched
        x = b.months[month]
        j.month(month).update({"status": "loading", "expires_ms": x["cd"] + ret, "retention": a.retention, "docs": x["docs"]})
        for dst in (MAIN_PREFIX + month, CLOUD_PREFIX + month):
            if dst not in present:
                must(api("PUT", "/%s" % dst, {"settings": {"index.creation_date": x["cd"], "index.refresh_interval": "-1",
                                                           "index.plugins.index_state_management.auto_manage": False}}), "create %s" % dst)
            else:   # left by an interrupted run: open it for the rerun
                must(api("PUT", "/%s/_settings" % dst, {"index.blocks.write": False, "index.refresh_interval": "-1"}), "reopen %s" % dst)   # strict
    j.save()
    todo, skip = [], 0
    srcs = {s for k in load for s in b.months[k]["srcs"]}
    for n_, ent in sorted(b.man["indices"].items()):
        if n_ in b.skipped or n_ not in srcs:
            continue
        for f in ent["files"]:
            if f["file"] in state.d["files"]:
                skip += 1
            else:
                todo.append(f)
    todo.sort(key=lambda f: -f["docs"])
    out("%d file(s) to load, %d already recorded as loaded; months not loaded: %d expired, %d loaded earlier" % (
        len(todo), skip, len(expired), len(loaded)))
    tot = {"docs": 0, "created": 0, "existing": 0, "retried": 0, "rejected": 0, "cloud": 0, "paused_s": 0, "refused_batches": 0, "not_ready_s": 0}
    if a.breaker_max > 0:
        out("breaker guard: the load pauses while any node's parent breaker is above %.0f %% of its limit" % (100 * a.breaker_max))
    rejected = {"lock": threading.Lock(), "f": open(os.path.join(sdir, "rejected.ndjson"), "a")}
    t1 = time.time()
    nd = 0
    global DOWN
    DOWN = Down(shared=bool(a.procs))   # E4-deb N-F2a: one outage record for every process and thread of this load
    if a.procs:   # shaping in processes
        import multiprocessing
        ex = concurrent.futures.ProcessPoolExecutor(a.procs, mp_context=multiprocessing.get_context("fork"), initializer=_die_with_parent)
        futs = [ex.submit(load_file_proc, a, b, f) for f in todo]
    else:
        ex = concurrent.futures.ThreadPoolExecutor(a.workers)
        futs = [ex.submit(load_file, a, b, f, state, rejected) for f in todo]
    with ex:
        try:
            for fu in concurrent.futures.as_completed(futs):
                s_ = fu.result()
                if a.procs:
                    s_, f_, rej_ = s_
                    if rej_:
                        rejected["f"].write(rej_)
                        rejected["f"].flush()
                    if not s_["rejected"]:
                        state.done(f_, s_)
                for k in tot:
                    tot[k] += s_.get(k, 0)
                nd += 1
        except Exception:
            for fu in futs:
                fu.cancel()
            try:   # E4-deb N-F2a: the files already queued to the processes are not started (Python 3.9+)
                ex.shutdown(wait=True, cancel_futures=True)
            except TypeError:
                pass
            raise
    el = time.time() - t1
    out("loaded %d docs (%d created, %d already there, %d retried after 429, %d rejected; %d went to the cloud family) in %.1fs = %.0f docs/s" % (
        tot["docs"], tot["created"], tot["existing"], tot["retried"], tot["rejected"], tot["cloud"], el, tot["docs"] / el if el else 0))
    if tot["paused_s"] or tot["refused_batches"]:
        out("breaker guard: paused %.0f s in all for the parent breaker; %d batch(es) refused and sent again" % (tot["paused_s"], tot["refused_batches"]))
    if tot["not_ready_s"] or DOWN.total():
        # E4-deb N-F2b: wall-clock time without an answer (the processes' own waits overlap and were summed before)
        out("the indexer did not answer for %.0f s (wall clock) during the load (a restart): the load waited and went on" % DOWN.total())
    if tot["rejected"]:
        raise SystemExit("ERROR: %d document(s) were rejected by the indexer; see %s. The history stays off." % (
            tot["rejected"], os.path.join(sdir, "rejected.ndjson")))
    must(api("POST", "/%s/_refresh?allow_no_indices=true&ignore_unavailable=true" % ALL), "refresh the history indices")   # strict
    for month in load:
        x = b.months[month]
        main, cloud = MAIN_PREFIX + month, CLOUD_PREFIX + month
        have = count(api, "%s,%s" % (main, cloud))
        out("  %s: %d of %d" % (month, have, x["docs"]))
        if have != x["docs"]:
            raise SystemExit("ERROR %s: %d documents in the target, the bundle has %d. Rerun apply: it resumes." % (month, have, x["docs"]))
        targets = {}
        present = target_present(api)   # strict listing; a refused HEAD used to skip the index silently
        for dst in (main, cloud):
            if dst not in present:
                continue
            if count(api, dst) == 0:
                must(api("DELETE", "/%s" % dst), "delete the empty %s" % dst)
                continue
            targets[dst] = per_source_counts(api, dst)
        if sum(n for per in targets.values() for n in per.values()) != x["docs"]:
            raise SystemExit("ERROR %s: the per-index counts of %s do not add up to %d" % (month, sorted(targets), x["docs"]))
        # recorded BEFORE the policy goes on, so a kill between the two cannot leave a month the retention may
        # delete while the journal still says "loading" (a rerun would then re-create it)
        j.month(month).update({"status": "loaded", "loaded": iso(time.time() * 1000), "targets": targets})
        j.save()
        for dst in targets:
            finish_target(api, a, dst)
    # loaded months of earlier runs: make sure their retention is on (a kill may have come between journal and policy)
    present = target_present(api)
    for month in loaded:
        for dst in j.month(month).get("targets", {}):
            if dst in present:
                finish_target(api, a, dst, merge=False)
    out("apply finished in %.1fs (%.0f docs/s end to end); not loaded: %s" % (
        time.time() - T0, sum(b.months[k]["docs"] for k in load) / max(time.time() - T0, 0.001),
        ", ".join("%s (expired before the load)" % k for k in expired) or "nothing"))
    return 0


def finish_target(api, a, dst, merge=True):
    """Write block, retention policy (H1's end of apply, as one function)."""
    if merge:
        must(api("PUT", "/%s/_settings" % dst, {"index.refresh_interval": "5s"}), "refresh interval of %s" % dst)   # strict
        if a.forcemerge:
            must(api("POST", "/%s/_forcemerge?max_num_segments=1" % dst, timeout=3600), "force merge %s" % dst)
    must(api("PUT", "/%s/_settings" % dst, {"index.blocks.write": True}), "write block %s" % dst)
    s, ex_ = api("GET", "/_plugins/_ism/explain/%s" % dst)
    if s != 200:   # strict
        raise SystemExit("ERROR explain the retention of %s: HTTP %s %s" % (dst, s, json.dumps(ex_)[:600]))
    cur = (ex_.get(dst) or {}).get("index.plugins.index_state_management.policy_id")
    if cur and cur != POLICY:
        api("POST", "/_plugins/_ism/remove/%s" % dst)
    if cur != POLICY:
        r = must(api("POST", "/_plugins/_ism/add/%s" % dst, {"policy_id": POLICY}), "attach the retention policy to %s" % dst)
        if r.get("failures"):
            raise SystemExit("ERROR attaching the retention policy to %s: %s" % (dst, json.dumps(r)[:400]))


def cmd_prove(api, a, b):
    fails = 0

    def check(ok, good, bad):
        nonlocal fails
        out(("  ok   " + good) if ok else ("  FAIL " + bad))
        fails += 0 if ok else 1
    must(api("POST", "/%s/_refresh?allow_no_indices=true&ignore_unavailable=true" % ALL), "refresh the history indices")   # strict
    # what should be there now, from the journal: months expired before the load are not expected; a target index
    # of a loaded month past its retention date may be gone (the retention deleted it), never partial.
    j = Journal(os.path.join(state_dir(a, b), "journal.json"))
    for attempt in (1, 2):    # the retention may delete an index while the proof runs: then count again once
        before = target_present(api)
        _, expired, loaded_ = classify_months(api, a, b, j, time.time() * 1000, quiet=(attempt == 2))
        want, gone_docs, gone = {}, 0, []
        for k, x in sorted(b.months.items()):
            e = j.month(k)
            if k in expired:
                continue
            if e.get("status") != "loaded":         # not loaded by this tool's journal: the whole month is expected
                for s_ in x["srcs"]:
                    if b.man["indices"][s_]["docs_expected"]:
                        want[s_] = b.man["indices"][s_]["docs_expected"]
                continue
            if sum(n_ for per in e.get("targets", {}).values() for n_ in per.values()) != x["docs"]:
                check(False, "", "journal: month %s is recorded as loaded but its targets do not add up to %d" % (k, x["docs"]))
            for t, per in e.get("targets", {}).items():
                if t in e.get("deleted_by_retention", {}):
                    gone.append(t)
                    gone_docs += sum(per.values())
                    continue
                for s_, n_ in per.items():
                    want[s_] = want.get(s_, 0) + n_
        mine = {"terms": {"legacy.index": sorted(want)}}
        tot = count(api, ALL, mine) if want else 0
        s, o = api("POST", "/%s/_search?ignore_unavailable=true&allow_no_indices=true" % ALL,
                   {"size": 0, "query": mine, "aggs": {"i": {"terms": {"field": "legacy.index", "size": 20000}}}})
        got = {x["key"]: x["doc_count"] for x in o.get("aggregations", {}).get("i", {}).get("buckets", [])} if s == 200 else {}
        if target_present(api).keys() == before.keys():
            break
        out("  (a history index was deleted while counting: counting again)")
    exp_total = sum(want.values())
    if expired:
        out("  info not expected: %s, expired before the load (%d documents, retention %s)" % (
            ", ".join(expired), sum(b.months[k]["docs"] for k in expired), a.retention))
    if gone:
        out("  info deleted by the retention since the load, as planned: %s (%d documents)" % (", ".join(sorted(gone)), gone_docs))
    check(tot == exp_total, "documents: %d = expected %d (bundle %d)" % (tot, exp_total, b.total()),
          "documents: %d, expected %d (bundle %d)" % (tot, exp_total, b.total()))
    diff = sorted(k for k in set(got) | set(want) if got.get(k) != want.get(k))
    check(not diff, "per 4.x index: all %d expected source indices have their exact count" % len(want),
          "per 4.x index: %d differ, e.g. %s" % (len(diff), [(k, want.get(k), got.get(k)) for k in diff[:4]]))
    a._expected = (exp_total, sorted(want))
    for q, name in (({"term": {"tags": "v4-legacy"}}, "tags:v4-legacy"), ({"exists": {"field": "legacy.id"}}, "legacy.id"),
                    ({"exists": {"field": "wazuh.cluster.name"}}, "wazuh.cluster.name"),
                    ({"exists": {"field": "wazuh.integration.name"}}, "wazuh.integration.name"),
                    ({"exists": {"field": "@timestamp"}}, "@timestamp")):
        n = count(api, ALL, {"bool": {"filter": [q, mine]}})
        check(n == tot, "%s on all %d" % (name, n), "%s on %d of %d" % (name, n, tot))
    # the two additions, reported (not every alert has a full_log or a registry agent)
    out("  info message (from full_log) on %d; wazuh.agent.groups on %d" % (
        count(api, ALL, {"bool": {"filter": [{"exists": {"field": "message"}}, mine]}}),
        count(api, ALL, {"bool": {"filter": [{"exists": {"field": "wazuh.agent.groups"}}, mine]}})))
    st = must(api("GET", "/%s/_settings/index.blocks.*?flat_settings=true&allow_no_indices=true" % ALL), "settings")
    check(all(v["settings"].get("index.blocks.write") == "true" for v in st.values()), "index.blocks.write on all %d indices" % len(st),
          "an index is not write-blocked")
    pol = {}
    for _ in range(30 if target_present(api) else 0):     # _ism/add is asynchronous; no index, nothing to explain
        s, ex_ = api("GET", "/_plugins/_ism/explain/%s" % ALL)
        if s != 200:   # strict; an empty (refused) answer passed the check
            raise SystemExit("ERROR explain the retention of the history: HTTP %s %s" % (s, json.dumps(ex_)[:600]))
        pol = {k: v.get("index.plugins.index_state_management.policy_id") for k, v in ex_.items() if isinstance(v, dict)}
        if all(p == POLICY for p in pol.values()):     # no index left (all expired) is fine too
            break
        time.sleep(3)
    check(all(p == POLICY for p in pol.values()), "retention: all %d indices on %s" % (len(pol), POLICY), "ISM policies: %s" % pol)
    rej = os.path.join(state_dir(a, b), "rejected.ndjson")
    nrej = sum(1 for _ in open(rej)) if os.path.exists(rej) else 0
    check(nrej == 0, "no document was rejected at load", "%d rejected document(s) recorded in %s" % (nrej, rej))
    out("PROOF: " + ("OK" if not fails else "%d check(s) failed" % fails))
    if not fails and os.path.isdir(state_dir(a, b)):
        j.d["proven"] = iso(time.time() * 1000)
        j.save()
    return 1 if fails else 0


def role_matches(patterns, name):
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def cmd_audit_roles(api, a, b):
    """Rule 9 of the design: before the switch, list the roles that would lose or gain."""
    roles = must(api("GET", "/_plugins/_security/api/roles"), "read roles")
    streams = ["wazuh-findings-v5-" + c for c in ("access-management", "applications", "cloud-services", "network-activity",
                                                   "other", "security", "system-activity", "unclassified")]
    res = {"lose_modules": [], "gain_history": [], "fls_leak": [], "dls": []}
    for name, r in sorted(roles.items()):
        for ip in r.get("index_permissions", []):
            pats = ip.get("index_patterns", [])
            reads = any(x in ("read", "search", "*", "indices_all", "crud", "indices:data/read/*", "indices:data/read/search*")
                        or x.startswith("indices:data/read") for x in ip.get("allowed_actions", []))
            if not reads:
                continue
            hit = [s for s in streams if role_matches(pats, s)]
            if not hit:
                continue
            covers = role_matches(pats, ALIAS_MAIN) and role_matches(pats, ALIAS_CLOUD)
            (res["gain_history"] if covers else res["lose_modules"]).append(name)
            if ip.get("fls"):
                res["fls_leak"].append({"role": name, "fls": ip["fls"]})
            if ip.get("dls"):
                res["dls"].append({"role": name, "dls": ip["dls"]})
    for k in ("lose_modules", "gain_history"):
        res[k] = sorted(set(res[k]))
    out("roles that read findings by a pattern that also covers the history aliases (they will read the 4.x alerts): %s" % res["gain_history"])
    out("roles that name finding streams exactly (403 on every module once the aliases are on): %s" % res["lose_modules"])
    out("roles with field-level security on findings (legacy.alert.* repeats the values under 4.x names): %s" % res["fls_leak"])
    out("roles with document-level security on findings (applies to the history as written): %s" % res["dls"])
    if a.json_out:
        write_json(a.json_out, res)
    if res["lose_modules"] and not a.accept_role_loss:
        out("REFUSE: fix or accept the exact-name roles (--accept-role-loss) before switching the history on")
        return 3
    return 0


def alias_actions(api, verb):
    acts = []
    idx = [t["index"] for t in existing_targets(api)]
    if any(i.startswith(MAIN_PREFIX) for i in idx):
        acts.append({verb: {"index": MAIN_PREFIX + "*", "alias": ALIAS_MAIN}})
    if any(i.startswith(CLOUD_PREFIX) for i in idx):
        acts.append({verb: {"index": CLOUD_PREFIX + "*", "alias": ALIAS_CLOUD}})
    return acts


def cmd_on(api, a, b):
    # Merged (rule 9): the proof always runs inside `on`; the lab switch --unproven of H1/M3/H5/S5 is removed, so the
    # proof cannot be bypassed (S5 found `on` bypassable by the caller's order; the flag was a second bypass).
    if cmd_prove(api, a, b) != 0:
        raise SystemExit("the history is not proven: not switching it on")
    # rule 9's second half inside the command, not only in the caller's order (`on` alone switched the history on
    # over an exact-name role that then lost every module): refuse while such a role exists, unless accepted.
    if cmd_audit_roles(api, a, b) != 0:
        raise SystemExit("a role would lose every module: not switching the history on (fix it, or --accept-role-loss)")
    acts = alias_actions(api, "add")
    if acts:
        must(api("POST", "/_aliases", {"actions": acts}), "add aliases")
    # what the proof expected (months expired before the load, or deleted by the retention since, are not expected)
    want, srcs = getattr(a, "_expected", (b.total(), sorted(n for n in b.man["indices"] if n not in b.skipped)))
    # count through the two alias names, not through wazuh-findings-v5*: the wildcard needs read on every native
    # finding stream, which the transport user does not otherwise need. The stock pattern covers the aliases by name:
    assert all(fnmatch.fnmatchcase(x, FINDINGS[0]) for x in (ALIAS_MAIN, ALIAS_CLOUD))
    names = ",".join(x["add"]["alias"] for x in acts)
    seen = count(api, names, {"terms": {"legacy.index": srcs}}) if srcs and names else 0
    out("aliases on (%d action(s), one request); through %s (inside %s): %d of %d expected history documents of this bundle" % (
        len(acts), names, FINDINGS[0], seen, want))
    rc = 0 if seen == want else 1
    if rc == 0:
        j = Journal(os.path.join(state_dir(a, b), "journal.json"))
        j.d["on"] = iso(time.time() * 1000)
        j.save()
        if a.remove_bundle:
            return cmd_remove_bundle(api, a, b, proven=True)
    return rc


def cmd_off(api, a, b):
    acts = [x for x in alias_actions(api, "remove")]
    s, o = api("POST", "/_aliases", {"actions": acts})
    seen = count(api, ALIAS_MAIN + "," + ALIAS_CLOUD, {"term": {"tags": "v4-legacy"}})   # the alias names, see cmd_on
    out("aliases off: HTTP %s; through the two alias names: %d history documents" % (s, seen))
    return 0


def cmd_remove_bundle(api, a, b, proven=False):
    """H5: delete what holds alert content (the dump files, the rejected-document log, temporary files) once the proof
    passes; keep the manifest, the 4.x mappings, the load state and the journal, so a rerun and the proof still work."""
    sdir = state_dir(a, b)
    j = Journal(os.path.join(sdir, "journal.json"))
    if j.d.get("bundle_data_removed"):
        out("bundle data already removed on %s" % j.d["bundle_data_removed"]["at"])
        return 0
    if not proven and cmd_prove(api, a, b) != 0:
        raise SystemExit("REFUSE: the history is not proven; the bundle is its only copy and is kept")
    j = Journal(os.path.join(sdir, "journal.json"))
    before = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(b.path) for f in fs)
    removed, nbytes = [], 0
    data = os.path.join(b.path, "data")
    for r, ds, fs in os.walk(data, topdown=False):
        for f in fs:
            p = os.path.join(r, f)
            nbytes += os.path.getsize(p)
            os.remove(p)
            removed.append(p)
        for d in ds:
            os.rmdir(os.path.join(r, d))
    if os.path.isdir(data):
        os.rmdir(data)
    for r, _, fs in os.walk(b.path):
        for f in fs:
            p = os.path.join(r, f)
            if f.startswith("rejected.ndjson") or f.endswith(".tmp") or f.endswith(".part"):
                nbytes += os.path.getsize(p)
                os.remove(p)
                removed.append(p)
    j.d["bundle_data_removed"] = {"at": iso(time.time() * 1000), "files": len(removed), "bytes": nbytes}
    j.save()
    left = []
    for r, _, fs in os.walk(b.path):
        for f in fs:
            p = os.path.join(r, f)
            left.append((os.path.relpath(p, b.path), os.path.getsize(p)))
    after = sum(n for _, n in left)
    out("bundle data removed: %d file(s), %.1f MB (bundle %.1f MB -> %.1f MB)" % (len(removed), nbytes / 1048576.0, before / 1048576.0, after / 1048576.0))
    kinds = {}
    for p, n in left:
        k = p.split(os.sep)[0]
        kinds.setdefault(k, [0, 0])
        kinds[k][0] += 1
        kinds[k][1] += n
    out("left in the bundle (no alert content; needed by a rerun and the proof): %s" % ", ".join(
        "%s %d file(s) %.1f KB" % (k, c, n / 1024.0) for k, (c, n) in sorted(kinds.items())))
    if os.path.abspath(sdir) != os.path.join(b.path, "load-state"):
        out("load state and journal outside the bundle: %s" % sdir)
    return 0


def cmd_status(api, a, b):
    j = Journal(os.path.join(state_dir(a, b), "journal.json"))
    for k, e in sorted(j.d.get("months", {}).items()):
        out("  month %s: %s%s%s" % (k, e.get("status"), (", expires %s" % iso(e["expires_ms"])) if e.get("expires_ms") else "",
                                     (", deleted by the retention: %s" % e["deleted_by_retention"]) if e.get("deleted_by_retention") else ""))
    for x in ("proven", "on", "bundle_data_removed"):
        if j.d.get(x):
            out("  %s: %s" % (x, j.d[x]))
    for t in existing_targets(api):
        out("  %-40s %8s docs  %s" % (t["index"], t["docs.count"], t["status"]))
    s, o = api("GET", "/_cat/aliases/%s,%s?format=json&h=alias,index" % (ALIAS_MAIN, ALIAS_CLOUD))
    out("aliases: %s" % (sorted("%s->%s" % (x["alias"], x["index"]) for x in o) if s == 200 and isinstance(o, list) else "none"))
    out("through the two alias names: %d history documents" % count(api, ALIAS_MAIN + "," + ALIAS_CLOUD, {"term": {"tags": "v4-legacy"}}))
    return 0


def cmd_rollback(api, a, b):
    if not a.yes:
        out("dry run (add --yes): would remove the two aliases, delete %s, template, pipeline and policy" % ALL)
        return 0
    cmd_off(api, a, b)
    for t in existing_targets(api):
        api("POST", "/_plugins/_ism/remove/%s" % t["index"])
        s, r = api("DELETE", "/%s" % t["index"])
        out("  DELETE %s: %s" % (t["index"], s))
    for what, path in (("template", "/_index_template/%s" % TEMPLATE), ("pipeline", "/_ingest/pipeline/%s" % PIPELINE),
                       ("policy", "/_plugins/_ism/policies/%s" % POLICY)):
        s, r = api("DELETE", path)
        out("  %s: %s" % (what, s))
    sdir = state_dir(a, b)    # a new apply must start clean; H1's rollback kept state.json, so apply skipped every file
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    for f in ("state.json", "journal.json", "rejected.ndjson"):
        p = os.path.join(sdir, f)
        if os.path.exists(p):
            os.rename(p, p + ".rolled-back-" + stamp)
            out("  %s archived as %s.rolled-back-%s" % (f, f, stamp))
    return 0


def _die_with_parent():
    """E2-deb fix 3: a shaping worker must not outlive the loader. A SIGKILL of the loader (the OOM killer, a crash) left its --procs workers as orphans of PID 1 holding the step's output pipe, and
    migrate.sh waited on them forever. Linux prctl(PR_SET_PDEATHSIG, SIGKILL); a
    worker whose parent is already gone exits at once."""
    import ctypes
    import signal
    parent = os.getppid()
    try:
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL)   # PR_SET_PDEATHSIG = 1
    except Exception:
        pass
    if os.getppid() != parent:      # the parent died before the call above took effect
        os._exit(1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["plan", "apply", "prove", "audit-roles", "on", "off", "status", "rollback", "remove-bundle"])
    ap.add_argument("--bundle", required=True, help="history bundle written by dump.py")
    ap.add_argument("--url", default="https://127.0.0.1:9200")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", help="default: env INDEXER_PASSWORD")
    ap.add_argument("--cacert")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--resolve", action="append")
    ap.add_argument("--cluster-name", help="wazuh.cluster.name of the 5.0 deployment (default: read from native documents)")
    ap.add_argument("--agent-ids", choices=["carried", "not-carried"], default="carried",
                    help="whether the 4.x agent registry was imported into 5.0; if not, wazuh.agent.id is not filled")
    ap.add_argument("--agent-registry", help="H1: JSON {agents: {id: {name, groups}}} of the 4.x registry, for the group stamp")
    ap.add_argument("--retention", default="365d")
    ap.add_argument("--priority", type=int, default=500)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--bulk-docs", type=int, default=2000)
    ap.add_argument("--bulk-bytes", type=int, default=8 << 20)
    ap.add_argument("--state-dir")
    ap.add_argument("--allow-incomplete", action="store_true")
    ap.add_argument("--no-forcemerge", dest="forcemerge", action="store_false")
    ap.add_argument("--accept-role-loss", action="store_true")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--load-expired", action="store_true", help="H5: also load months already past the retention")
    ap.add_argument("--remove-bundle", action="store_true", help="H5: with on, delete the bundle's alert files once on")
    ap.add_argument("--breaker-max", type=float, default=0.85,
                    help="pause while any node's parent breaker is above this fraction of its limit (0: never read it)")
    ap.add_argument("--breaker-wait-max", type=float, default=1800,
                    help="seconds of continuous breaker pressure or refusals before the load stops (it resumes with the same command)")
    ap.add_argument("--procs", type=int, default=0, help="H5: shape and send in N processes instead of --workers threads")
    a = ap.parse_args()
    b = Bundle(a.bundle)
    api = Api(a)
    fn = {"plan": cmd_plan, "apply": cmd_apply, "prove": cmd_prove, "audit-roles": cmd_audit_roles, "on": cmd_on, "off": cmd_off,
          "status": cmd_status, "rollback": cmd_rollback, "remove-bundle": cmd_remove_bundle}[a.cmd]
    try:
        r = fn(api, a, b)
    except RuntimeError as e:   # E4-deb N-F2a: a resumable stop is one line, not two Python tracebacks
        out("ERROR %s" % e)
        sys.exit(1)
    sys.exit(r if isinstance(r, int) else 0)


if __name__ == "__main__":
    main()
