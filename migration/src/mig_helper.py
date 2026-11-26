#!/usr/bin/env python3
"""Helper for migrate.sh. Built on arm F1/f1a's mig_helper.py. Python standard library only.

4.x side
  truth4 <outdir>               state of the RUNNING 4.x all-in-one, through its API (taken in pre-copy)
  fingerprint <outdir>          state of the FROZEN 4.x host (manager stopped): registry read from global.db, files,
                                 indexer counts. What phase 8 compares 5.0 against.
  export-saved-objects <out>    saved objects of the 4.x dashboard as ndjson
  export-security-rest <dir>    4.x indexer users, roles and mappings through the REST API, plus the shipped YAML
  bundle-ids <history-bundle>   count distinct document ids per 4.x index in the dump files against the manifest
  source-version <node> <component> <version> ...   only the latest 4.14.x is a source; exit 1 otherwise
  source-version-cluster [NODE,...]   the same for every manager node of the 4.x cluster, from /cluster/nodes; a node the
                                 inventory (CLUSTER_NODES) or the agent registry names that is not connected is refused
  retention-4x <out.json>       ISM policies covering the alert indices and their delete age; every
                                 policy's body and each alert index's policy into ism-4x.json beside it
  ism-restore4 <ism-4x.json>    going back: the 4.x ISM policies and their attachments put back
5.0 side
  setup-status                  the indexer setup status and the manager's content synchronisation
  handshake <addresses-file> <port>   one TLS handshake per dialled address against the agent listener certificate
  reconcile-membership <bundle> [--apply]   compare real agents, groups and memberships with the fingerprint; repair
  import-security <bundle>      custom indexer users, roles, mappings; additions to stock mappings; 4.x alert roles
                                 translated to the findings name space (document-level security rewritten)
  import-saved-objects <ndjson> custom dashboards as a view of the migrated history
  policy-unclassified get|on|off      index_unclassified_events of the standard space
  truth5 <outdir>               the same state on the running 5.0 all-in-one
  compare <truth4> <fingerprint> <truth5>   table of carried, lost, changed; exit 1 on a loss
  wait-agents <truth4> <secs> <opened-iso>        wait for a keepalive NEWER than the opening from every agent that was active

Credentials come from the environment, never from the command line:
  V4_API_PASSWORD, V4_INDEXER_ADMIN_PASSWORD (4.x);  the 5.0 ones are read from the export/credentials.env files.
"""
import base64, glob, gzip, hashlib, json, os, re, socket, sqlite3, ssl, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # loopback only


def http(method, url, user=None, password=None, token=None, body=None, headers=None, timeout=120, ctx=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    if token:
        h["Authorization"] = "Bearer " + token
    elif user is not None:
        h["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, context=ctx or CTX, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e).encode()


def jget(method, url, **kw):
    code, raw = http(method, url, **kw)
    try:
        return code, json.loads(raw.decode() or "null")
    except ValueError:
        return code, {"_raw": raw.decode(errors="replace")[:500]}


def envfile(path, key):
    try:
        for line in open(path):
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return None


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()


def fsha(path):
    try:
        return sha(open(path, "rb").read())
    except OSError:
        return None


def norm_sha(path):
    """agent.conf: the 5.0 API re-indents the file it is given, so compare it without leading and trailing blanks."""
    try:
        return sha("\n".join(l.strip() for l in open(path, errors="replace").read().splitlines() if l.strip()))
    except OSError:
        return None


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Api:
    """Wazuh Server API on loopback."""

    def __init__(self, password, user="wazuh"):
        self.base = "https://localhost:55000"
        code, raw = http("POST", self.base + "/security/user/authenticate?raw=true", user=user, password=password)
        if code != 200:
            raise SystemExit(f"Server API login as {user} failed: HTTP {code} {raw[:200]!r}")
        self.token = raw.decode().strip()

    def get(self, path):
        code, d = jget("GET", self.base + path, token=self.token)
        return d.get("data", {}).get("affected_items", []) if code == 200 else {"_error": code, "_body": d}

    def call(self, method, path, body=None, headers=None):
        return jget(method, self.base + path, token=self.token, body=body, headers=headers)


def api_password5():
    return os.environ.get("V5_API_PASSWORD") or envfile("/etc/wazuh-manager/export/credentials.env", "WAZUH_MANAGER_API_PASSWORD")


def idx_password5():
    if os.environ.get("MIG_IDX5_PASSWORD"):  # S5 lab adapter: the Docker lab has no /etc/wazuh-indexer/export
        return os.environ["MIG_IDX5_PASSWORD"]
    return envfile("/etc/wazuh-indexer/export/credentials.env", "WAZUH_INDEXER_ADMIN_PASSWORD")


def _short_digest(m):
    """R2: a 10-byte digest to count distinct ids. Python's blake2b is OpenSSL's on a FIPS host (the 4.14 OVA boots
    with fips_enabled=1) and refuses digest_size there; SHA-256 cut to 10 bytes serves the same count."""
    try:
        return hashlib.blake2b(m, digest_size=10).digest()
    except (TypeError, ValueError):
        return hashlib.sha256(m).digest()[:10]


def idx_host():
    """R2: the address the indexer listens on: loopback for the assistant's all-in-one, the private address for the
    5.0 Ansible role (network.host set to it alone)."""
    if os.environ.get("MIG_IDX5_HOST"):  # S5 lab adapter: the indexer's name on the Docker network
        return os.environ["MIG_IDX5_HOST"]
    try:
        for line in open("/etc/wazuh-indexer/opensearch.yml"):
            if line.startswith("network.host:"):
                h = line.split(":", 1)[1].strip().strip("'\"")
                return "127.0.0.1" if h in ("", "0.0.0.0", "127.0.0.1", "localhost") or h.startswith(("_", "[")) else h
    except OSError:
        pass
    return "127.0.0.1"


def idx(method, path, password, body=None, user="admin", timeout=120):
    """F4 (cluster retention): MIG_IDX_URL points the call at an indexer on another host (the cluster's master reads and
    restores the 4.x ISM policies through indexer node-1, as history-dump.sh does); with MIG_IDX_CAFILE the certificate
    is verified against that CA, as dump.py does with --cafile. Without them: this host's indexer, loopback, unverified."""
    base = os.environ.get("MIG_IDX_URL", "").rstrip("/") or "https://%s:9200" % idx_host()
    ctx = ssl.create_default_context(cafile=os.environ["MIG_IDX_CAFILE"]) if os.environ.get("MIG_IDX_CAFILE") and base.startswith("https:") else None
    kw = {"ctx": ctx} if ctx else {}
    return jget(method, base + path, user=user, password=password, body=body, timeout=timeout, **kw)


def client_keys(path):
    out = {}
    try:
        for line in open(path):
            p = line.split()
            if len(p) >= 4 and not p[1].startswith("!") and not line.startswith("#"):
                out[p[0]] = {"name": p[1], "ip": p[2], "key_sha256": sha(p[3])}
    except OSError:
        pass
    return out


def group_dirs(shared):
    out = {}
    if os.path.isdir(shared):
        for g in sorted(os.listdir(shared)):
            d = os.path.join(shared, g)
            if os.path.isdir(d):
                out[g] = {f: (norm_sha(os.path.join(d, f)) if f == "agent.conf" else fsha(os.path.join(d, f)))
                          for f in sorted(os.listdir(d)) if f not in ("merged.mg", "ar.conf")}
    return out


def security_objects(pw):
    sec = {}
    for kind in ("internalusers", "roles", "rolesmapping", "actiongroups", "tenants"):
        code, d = idx("GET", "/_plugins/_security/api/" + kind, pw)
        sec[kind] = d if code == 200 else {"_error": code}
    return sec


SHIPPED_FILES = {"internalusers": "internal_users.yml", "roles": "roles.yml", "rolesmapping": "roles_mapping.yml",
                 "actiongroups": "action_groups.yml", "tenants": "tenants.yml"}


# Names of the security objects a 4.14.x package ships that the API does NOT flag reserved, static or hidden, and the
# users its stock mappings hold (read from the pristine YAML of a fresh 4.14.10 install). A fixed list, because the YAML
# on a host is not a reference: a site may manage users by editing it, and a return to 4.x rewrites it.
STOCK_4_14 = {
 "internalusers": [
  "admin",
  "anomalyadmin",
  "kibanaro",
  "kibanaserver",
  "logstash",
  "readall",
  "snapshotrestore"
 ],
 "roles": [
  "alerting_ack_alerts",
  "alerting_full_access",
  "alerting_read_access",
  "anomaly_full_access",
  "anomaly_read_access",
  "asynchronous_search_full_access",
  "asynchronous_search_read_access",
  "cross_cluster_replication_follower_full_access",
  "cross_cluster_replication_leader_full_access",
  "cross_cluster_search_remote_full_access",
  "index_management_full_access",
  "ip2geo_datasource_full_access",
  "ip2geo_datasource_read_access",
  "kibana_read_only",
  "knn_full_access",
  "knn_read_access",
  "manage_wazuh_index",
  "ml_full_access",
  "ml_read_access",
  "notebooks_full_access",
  "notebooks_read_access",
  "notifications_full_access",
  "notifications_read_access",
  "observability_full_access",
  "observability_read_access",
  "point_in_time_full_access",
  "ppl_full_access",
  "reports_full_access",
  "reports_instances_read_access",
  "reports_read_access",
  "security_analytics_ack_alerts",
  "security_analytics_full_access",
  "security_analytics_read_access",
  "security_rest_api_access",
  "security_rest_api_full_access",
  "snapshot_management_full_access",
  "snapshot_management_read_access"
 ],
 "rolesmapping": [
  "all_access",
  "kibana_server",
  "kibana_user",
  "logstash",
  "manage_snapshots",
  "manage_wazuh_index",
  "own_index",
  "readall"
 ],
 "actiongroups": [],
 "tenants": [
  "admin_tenant"
 ],
 "mapping_users": {
  "own_index": [
   "*"
  ],
  "kibana_server": [
   "kibanaserver"
  ],
  "manage_wazuh_index": [
   "kibanaserver"
  ]
 }
}


def shipped_names(directory, kind):
    """Stock object names of a 4.14.x install (fixed list); `directory` is only read for a kind the list does not have."""
    if kind in STOCK_4_14:
        return set(STOCK_4_14[kind])
    try:
        text = open(os.path.join(directory, SHIPPED_FILES[kind])).read()
    except (OSError, KeyError):
        return set()
    return {m.group(1).strip("'\"") for m in re.finditer(r"^([^\s#][^:\n]*):\s*$", text, re.M)} - {"_meta"}


def shipped_mapping_users(directory):
    """{role: [users...]} of the roles_mapping.yml the 4.x package installed (to find users a site ADDED to a stock mapping)."""
    if "mapping_users" in STOCK_4_14:
        return {r: list(STOCK_4_14["mapping_users"].get(r, [])) for r in STOCK_4_14["rolesmapping"]}
    out, cur, inusers = {}, None, False
    try:
        lines = open(os.path.join(directory, "roles_mapping.yml")).read().splitlines()
    except OSError:
        return out
    for l in lines:
        m = re.match(r"^([^\s#][^:\n]*):\s*$", l)
        if m:
            cur, inusers = m.group(1).strip("'\""), False
            out.setdefault(cur, [])
            continue
        if cur is None:
            continue
        if re.match(r"^\s+users:\s*$", l):
            inusers = True
            continue
        m = re.match(r"^\s+-\s*\"?([^\"\n]+?)\"?\s*$", l)
        if inusers and m:
            out[cur].append(m.group(1))
        elif not re.match(r"^\s+-", l):
            inusers = False
    return out


def custom(d, shipped=()):
    return {k: v for k, v in d.items() if isinstance(v, dict) and k not in shipped
            and not (v.get("reserved") or v.get("static") or v.get("hidden"))}


def saved_objects(base, user, pw):
    out = []
    types = "&".join("type=" + t for t in ("dashboard", "visualization", "search", "index-pattern", "query"))
    code, d = jget("GET", f"{base}/api/saved_objects/_find?{types}&per_page=1000", user=user, password=pw, headers={"osd-xsrf": "true"})
    if code != 200:
        return {"_error": code, "_body": d}
    for o in d.get("saved_objects", []):
        out.append({"type": o["type"], "id": o["id"], "title": o.get("attributes", {}).get("title")})
    return sorted(out, key=lambda o: (o["type"], o["id"]))


def indices(pw, pattern):
    code, d = idx("GET", f"/_cat/indices/{pattern}?format=json&h=index,docs.count,store.size,health&expand_wildcards=all", pw)
    if code != 200:
        return {"_error": code}
    out = {i["index"]: int(i["docs.count"] or 0) for i in d}
    # E5 fold (RD3's nested count in its second place): _cat docs.count also counts nested sub-documents (the
    # 4.x template maps data.ms-graph.evidence as nested), while dump.py counts with _count since the RD3 fold, so phase 4
    # refused every source holding Microsoft Graph alerts with evidence ("551790 alerts at the freeze; the dump manifest
    # has ... 551770") and the history compare would have read LOST. The 4.x alert indices, the only ones compared with
    # the dump and the history, are counted with _count (top-level documents); a refused _count is an error (rule 19).
    for name in [n for n in out if re.match(r"wazuh-alerts-4\.x-", n)]:
        c2, n2 = idx("GET", "/%s/_count" % urllib.parse.quote(name, safe=""), pw)
        if c2 != 200 or not isinstance(n2, dict) or "count" not in n2:
            return {"_error": c2}
        out[name] = int(n2["count"])
    return out


def write(outdir, name, obj):
    # the decisions file is read back by every rerun (load() takes an unreadable file as empty, so a
    # file cut in half would lose the user's answers): written whole or not at all
    durable_json(os.path.join(outdir, name), obj)


def load(d, name):
    try:
        return json.load(open(os.path.join(d, name)))
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------ 4.x
O = "/var/ossec"


def files_state(outdir):
    """Everything that can be read from files and from the indexer, with or without a running manager."""
    write(outdir, "client_keys.json", client_keys(O + "/etc/client.keys"))
    write(outdir, "group_files.json", group_dirs(O + "/etc/shared"))
    write(outdir, "enrollment.json", {"authd_pass_sha256": fsha(O + "/etc/authd.pass"),
                                       "authd_pass_bytes": len(open(O + "/etc/authd.pass", "rb").read().strip()) if os.path.exists(O + "/etc/authd.pass") else None})
    custom_files = {}
    for sub in ("rules", "decoders", "lists"):
        for root, _, files in os.walk(os.path.join(O, "etc", sub)):
            for f in files:
                p = os.path.join(root, f)
                custom_files[os.path.relpath(p, O)] = fsha(p)
    write(outdir, "ruleset_files.json", custom_files)
    conf = open(O + "/etc/ossec.conf").read()
    blocks = {t: len(re.findall(r"<%s>" % t, conf)) for t in
              ("email_alerts", "integration", "syslog_output", "active-response", "command", "localfile", "agentless", "cluster", "wodle")}
    blocks["email_notification"] = (re.findall(r"<email_notification>(\w+)<", conf) or [None])[0]
    lio = [l.strip() for l in open(O + "/etc/local_internal_options.conf") if l.strip() and not l.startswith("#")]
    write(outdir, "manager_settings.json", {"ossec_conf_blocks": blocks, "local_internal_options": lio, "ossec_conf_sha256": sha(conf)})
    ipw = os.environ["V4_INDEXER_ADMIN_PASSWORD"]
    sec = security_objects(ipw)
    # which names are stock: the YAML the 4.x package installed. After going back those files hold the restored
    # configuration, so the copy kept in the bundle is the reference then (SHIPPED_DIR).
    shipped = os.environ.get("SHIPPED_DIR") or "/etc/wazuh-indexer/opensearch-security"
    isec = {k: sorted(custom(v, shipped_names(shipped, k))) if "_error" not in v else v for k, v in sec.items()}
    sm = shipped_mapping_users(shipped)
    isec["stock_mapping_additions"] = {r: sorted(set(v.get("users", [])) - set(sm.get(r, [])))
                                       for r, v in (sec.get("rolesmapping") or {}).items()
                                       if isinstance(v, dict) and r in sm and set(v.get("users", [])) - set(sm.get(r, []))}
    write(outdir, "indexer_security.json", isec)
    write(outdir, "saved_objects.json", saved_objects("https://127.0.0.1:443", "admin", ipw))
    write(outdir, "indices.json", indices(ipw, "wazuh-*"))
    code, d = idx("POST", "/wazuh-alerts-*/_search?size=0", ipw, body={
        "track_total_hits": True,
        "aggs": {"agents": {"terms": {"field": "agent.id", "size": 1000},
                            "aggs": {"last": {"max": {"field": "timestamp"}}, "first": {"min": {"field": "timestamp"}}}},
                 "rules": {"terms": {"field": "rule.id", "size": 5000}}}})
    if code == 200:
        write(outdir, "alerts.json", {
            "total": d["hits"]["total"]["value"],
            "per_agent": {b["key"]: {"count": b["doc_count"], "first": b["first"].get("value_as_string"), "last": b["last"].get("value_as_string")}
                          for b in d["aggregations"]["agents"]["buckets"]},
            "per_rule": {b["key"]: b["doc_count"] for b in d["aggregations"]["rules"]["buckets"]}})
        return d["hits"]["total"]["value"]
    return None


def truth4(outdir):
    api = Api(os.environ["V4_API_PASSWORD"])
    agents = api.get("/agents?select=id,name,status,version,group,ip,registerIP,os.name,os.platform,dateAdd,lastKeepAlive&limit=100000")
    write(outdir, "agents.json", agents)
    write(outdir, "groups_api.json", api.get("/groups?limit=100000"))
    write(outdir, "api_security.json", {k: api.get(f"/security/{k}?limit=500") for k in ("users", "roles", "policies", "rules")})
    n = files_state(outdir)
    write(outdir, "taken.json", {"at": now_iso(), "manager": "running"})
    print(f"truth4: {len(agents)} agent(s) (with 000), {len(group_dirs(O + '/etc/shared'))} group folder(s), {n} alert(s) indexed; written to {outdir}")


def fingerprint(outdir):
    """The frozen source. The API is down, so the registry is read from global.db (read-only)."""
    c = sqlite3.connect("file:%s/queue/db/global.db?mode=ro" % O, uri=True)
    agents = []
    member = {}
    for aid, g, _ in c.execute("select b.id_agent, g.name, b.priority from belongs b join `group` g on g.id=b.id_group order by b.id_agent, b.priority"):
        member.setdefault("%03d" % aid, []).append(g)
    for aid, name, ip, rip, ver, st, ka in c.execute("select id,name,ip,register_ip,version,connection_status,last_keepalive from agent order by id"):
        i = "%03d" % aid
        agents.append({"id": i, "name": name, "ip": ip, "registerIP": rip, "version": ver, "status": st, "group": member.get(i, []), "lastKeepAlive": ka})
    groups = [r[0] for r in c.execute("select name from `group` order by name")]
    c.close()
    write(outdir, "agents.json", agents)
    write(outdir, "groups.json", groups)
    write(outdir, "rbac_db.json", {"sha256": fsha(O + "/api/configuration/security/rbac.db")})
    n = files_state(outdir)
    write(outdir, "taken.json", {"at": now_iso(), "manager": "stopped"})
    h = hashlib.sha256()
    for f in sorted(os.listdir(outdir)):
        if f not in ("taken.json", "FINGERPRINT", "saved_objects.json"):
            h.update(f.encode() + b"\0" + open(os.path.join(outdir, f), "rb").read())
    open(os.path.join(outdir, "FINGERPRINT"), "w").write(h.hexdigest() + "\n")
    print(f"fingerprint {h.hexdigest()[:16]}…: {len(agents) - 1} agent(s), {len(groups)} group(s), {n} alert(s) indexed, taken with the manager stopped at {now_iso()}")


def export_saved_objects(out):
    pw = os.environ["V4_INDEXER_ADMIN_PASSWORD"]
    body = {"type": ["dashboard", "visualization", "search", "index-pattern", "query"], "includeReferencesDeep": True}
    code, raw = http("POST", os.environ.get("MIG_DASH4_URL", "https://127.0.0.1:443") + "/api/saved_objects/_export", user="admin", password=pw, body=body, headers={"osd-xsrf": "true"})
    if code != 200:
        raise SystemExit(f"saved objects export failed: HTTP {code} {raw[:300]!r}")
    open(out, "wb").write(raw)
    lines = [json.loads(l) for l in raw.decode().splitlines() if l.strip()]
    objs = [l for l in lines if "type" in l]
    print(f"export-saved-objects: {len(objs)} object(s): " + ", ".join(sorted(f"{o['type']}:{o['id']}" for o in objs)))


def export_security_rest(outdir):
    sec = security_objects(os.environ["V4_INDEXER_ADMIN_PASSWORD"])
    for k, v in sec.items():
        write(outdir, k + ".json", v)
    shipped = "/etc/wazuh-indexer/opensearch-security"
    os.makedirs(os.path.join(outdir, "..", "shipped"), exist_ok=True)
    for f in SHIPPED_FILES.values():
        try:
            open(os.path.join(outdir, "..", "shipped", f), "w").write(open(os.path.join(shipped, f)).read())
        except OSError:
            pass
    print("export-security-rest: " + ", ".join(f"{k}: {len(custom(v, shipped_names(shipped, k)))} custom of {len(v)}" for k, v in sec.items()))


def bundle_ids(bundle):
    """Phase 4: the dump files hold, per 4.x index, exactly as many DISTINCT ids as the index had at the freeze.
    (A pre-copy plus a delta can hold a document twice; the loader's `create` drops the second.)"""
    man = json.load(open(os.path.join(bundle, "manifest.json")))
    bad, tot, dup = [], 0, 0
    for name, ent in sorted(man["indices"].items()):
        ids, lines = set(), 0
        for f in ent["files"]:
            with gzip.open(os.path.join(bundle, f["file"]), "rb") as fh:
                while True:
                    m = fh.readline()
                    if not m:
                        break
                    fh.readline()
                    ids.add(_short_digest(m))
                    lines += 1
        tot += len(ids)
        dup += lines - len(ids)
        if len(ids) != ent["docs_expected"] or not ent["complete"]:
            bad.append((name, len(ids), ent["docs_expected"], ent["complete"]))
    print(f"bundle-ids: {len(man['indices'])} indices, {tot} distinct documents, {dup} present twice (pre-copy and delta); {len(bad)} index(es) differ from the source count")
    for b in bad[:10]:
        print("  DIFFERENT %s: %d distinct in the files, the source had %d, complete=%s" % b)
    return 1 if bad else 0


# ------------------------------------------------------------------ 5.0
M5ETC = "/etc/wazuh-manager"


def build_manifest():
    """Rule 4 and "Supported builds": the builds, tool, map and template versions this tool was validated on, and the
    build vocabulary its gates read (manifest/builds.json beside this file)."""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest", "builds.json")
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return {}


def setup_ready(statuses, vocab=None):
    """Pure decision of the setup-status gate (rule 4). statuses: the status of every .wazuh-setup-status document.
    Ready when at least one document reads a word of `required_one_of` and every document reads a word of `accepted`.
    An empty list (nothing read, or the read refused) is never ready."""
    vocab = vocab or {}
    req = [w.lower() for w in vocab.get("required_one_of", ["ready"])]
    acc = [w.lower() for w in vocab.get("accepted", ["ready", "up_to_date"])]
    st = [str(x).lower() for x in statuses]
    return bool(st) and any(x in req for x in st) and all(x in acc for x in st)


def setup_status():
    """'Installed' means the setup status is ready and the manager has synchronised its content, not that services are active."""
    pw = idx_password5()
    code, d = idx("GET", "/.wazuh-setup-status/_search?size=20", pw)
    docs = [h["_source"] for h in d.get("hits", {}).get("hits", [])] if code == 200 else []
    print("setup-status: HTTP %s %s" % (code, json.dumps(docs)[:600] if docs else json.dumps(d)[:300]))
    # F6/F7/F10 merged: the nightly of 2026-11-24 writes one document per index template (status "up_to_date", with
    # installed, shipped and compat versions) beside the one "ready" document (F6: 53 documents). F7 and F10 read only the
    # first 20 (size=20), saw only "up_to_date" and accepted it alone; reading all of them, the "ready" one is there too.
    # The words are build vocabulary, so they come from the build manifest (rule 4), not from this code.
    code2, d2 = idx("GET", "/.wazuh-setup-status/_search?size=1000", pw)
    docs = [h["_source"] for h in d2.get("hits", {}).get("hits", [])] if code2 == 200 else docs
    st = [str(x.get("status", "")).lower() for x in docs]
    print("setup-status: %d document(s), statuses %s" % (len(st), {k: st.count(k) for k in sorted(set(st))}))
    ready = setup_ready(st, build_manifest().get("setup_status", {}))
    code, d = idx("POST", "/wazuh-threatintel-policies/_search?size=10", pw, body={"_source": ["space", "document.enabled", "document.index_unclassified_events"]})
    spaces = {h["_source"].get("space", {}).get("name"): h["_source"].get("document", {}) for h in d.get("hits", {}).get("hits", [])} if code == 200 else {}
    print("content: policies per space: %s" % json.dumps(spaces))
    log = "/var/wazuh-manager/logs/wazuh-manager.log"
    sync_ok, sync_bad = 0, 0
    try:
        for l in open(log, errors="replace"):
            if "CM::Sync" in l or "cmsync" in l.lower():
                if "Failed" in l or "ERROR" in l:
                    sync_bad += 1
                else:
                    sync_ok += 1
    except OSError:
        pass
    print("manager content synchronisation: %d line(s), %d failure line(s) in %s" % (sync_ok + sync_bad, sync_bad, log))
    ok = ready and "standard" in spaces
    print("setup-status: %s" % ("READY" if ok else "NOT READY"))
    return 0 if ok else 1


def handshake(addr_file, port):
    """One TLS handshake per dialled address: the listener certificate must verify under the manager CA FOR THAT NAME."""
    ca = M5ETC + "/certs/root-ca.pem"
    addrs = [l.strip() for l in open(addr_file) if l.strip()]
    bad = 0
    for a in addrs:
        ctx = ssl.create_default_context(cafile=ca)
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=10) as s:
                with ctx.wrap_socket(s, server_hostname=a) as t:
                    cert = t.getpeercert()
                    sans = [v for k, v in cert.get("subjectAltName", ())]
                    print(f"handshake: {a}: OK on 127.0.0.1:{port} (TLS {t.version()}, certificate names {sans})")
        except (ssl.SSLError, OSError) as e:
            bad += 1
            print(f"handshake: {a}: FAILED: {e}")
    print(f"handshake: {len(addrs)} dialled address(es), {bad} failed")
    return 1 if bad else 0


def reconcile_membership(bundle, apply=""):
    """Compare the real 5.0 registry with the fingerprint and repair through the API. Never a second import, never --force."""
    fp = os.path.join(bundle, "fingerprint")
    want_agents = {a["id"]: a for a in load(fp, "agents.json") if a["id"] != "000"}
    want_groups = [g for g in load(fp, "groups.json")]
    keys = {}
    for line in open(os.path.join(bundle, "v4", "etc", "client.keys")):
        p = line.split()
        if len(p) >= 4 and not p[1].startswith("!"):
            keys[p[0]] = p
    api = Api(api_password5())
    have_groups = {g["name"] for g in api.get("/groups?limit=100000")}
    have = {a["id"]: a for a in api.get("/agents?select=id,name,group,status&limit=100000")}
    problems, fixed = [], 0
    do = apply == "--apply"
    on5 = {}
    try:
        for line in open("/etc/wazuh-manager/client.keys", errors="replace"):
            p_ = line.split()
            if len(p_) >= 4 and not p_[1].startswith(("!", "#")):
                on5[p_[0]] = p_[3]
    except OSError:
        pass
    for g in want_groups:
        if g not in have_groups:
            problems.append(f"group {g} is missing")
            if do:
                c, d = api.call("POST", "/groups", body={"group_id": g})
                conf = os.path.join(bundle, "v4", "etc", "shared", g, "agent.conf")
                if os.path.exists(conf):
                    c2, d2 = api.call("PUT", f"/groups/{g}/configuration", body=open(conf, "rb").read(), headers={"Content-Type": "application/xml"})
                else:
                    c2 = "-"
                print(f"reconcile: created group {g}: HTTP {c}; its agent.conf: HTTP {c2}")
                fixed += 1
    for i, a in sorted(want_agents.items()):
        if i not in have:
            problems.append(f"agent {i} {a['name']} is missing")
            if do and i in keys:
                c, d = api.call("POST", "/agents/insert", body={"id": i, "name": keys[i][1], "ip": keys[i][2], "key": keys[i][3]})
                print(f"reconcile: inserted agent {i}: HTTP {c} {json.dumps(d)[:160]}")
                have[i] = {"id": i, "name": keys[i][1], "group": ["default"]}
                fixed += 1
            else:
                continue
        if have[i].get("name") != a["name"]:
            problems.append(f"agent {i} is named {have[i].get('name')}, the bundle says {a['name']}")
        wg, hg = a.get("group") or ["default"], have[i].get("group") or []
        if wg != hg:
            problems.append(f"agent {i} {a['name']} is in {hg}, the bundle says {wg}")
            if do and not (i in on5 and i in keys and on5[i] != keys[i][3]):   # never an impostor
                c, d = api.call("PUT", f"/agents/{i}/group/{wg[0]}?force_single_group=true")
                codes = [c]
                for g in wg[1:]:
                    c, d = api.call("PUT", f"/agents/{i}/group/{g}")
                    codes.append(c)
                print(f"reconcile: agent {i}: membership set to {wg}: HTTP {codes}")
                fixed += 1
    # F7 (rule 5): an agent whose key on 5.0 differs from the bundle's enrolled by itself under that id; it is named and
    # never repaired (with --apply the earlier version gave such an impostor the groups of the real agent)
    impostors = sorted(i for i in want_agents if i in have and i in on5 and i in keys and on5[i] != keys[i][3])
    if impostors:
        problems.append(f"agents whose key on 5.0 differs from the bundle's (enrolled by themselves; never repaired): {impostors}")
    extra = sorted(set(have) - set(want_agents) - {"000"})
    if extra:
        problems.append(f"agents on 5.0 that the bundle does not carry: {extra} (not removed: an agent that enrolled by itself needs a decision)")
    for p in problems:
        print("reconcile: DIFFERENT " + p)
    if do and problems:
        time.sleep(3)
        have = {a["id"]: a for a in Api(api_password5()).get("/agents?select=id,name,group&limit=100000")}
        left = [i for i, a in want_agents.items() if (have.get(i, {}).get("group") or []) != (a.get("group") or ["default"])]
        print(f"reconcile: {fixed} repair(s) made; agents still different: {left}")
        return 1 if left or extra else 0
    print(f"reconcile: {len(want_agents)} agent(s), {len(want_groups)} group(s) compared with the fingerprint; {len(problems)} difference(s)")
    return 1 if problems else 0


# 4.x alert field -> 5.0 findings field, for document-level security filters only. Anything else is flagged, not guessed.
DLS_FIELDS = {"agent.id": "wazuh.agent.id", "agent.name": "wazuh.agent.name", "rule.id": "wazuh.rule.id", "rule.groups": "wazuh.rule.tags",
              "manager.name": "wazuh.cluster.node", "cluster.name": "wazuh.cluster.name", "location": "wazuh.protocol.location"}


def translate_dls(dls):
    """Rewrite field names in a 4.x DLS query. Returns (new, unknown-fields)."""
    try:
        q = json.loads(dls)
    except ValueError:
        return None, ["(not JSON)"]
    unknown = []
    leafq = {"term", "terms", "match", "match_phrase", "prefix", "wildcard", "range", "regexp", "fuzzy"}

    def walk(o, parent=None):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if parent in leafq:
                    if k in DLS_FIELDS:
                        out[DLS_FIELDS[k]] = v
                    else:
                        unknown.append(k)
                        out[k] = v
                elif k == "exists" and isinstance(v, dict) and "field" in v:
                    f = v["field"]
                    if f not in DLS_FIELDS:
                        unknown.append(f)
                    out[k] = {"field": DLS_FIELDS.get(f, f)}
                else:
                    out[k] = walk(v, k)
            return out
        if isinstance(o, list):
            return [walk(x, parent) for x in o]
        return o
    return json.dumps(walk(q), separators=(",", ":")), unknown


def import_security(bundle):
    """Custom indexer objects (hashes from the securityadmin backup), additions to stock mappings, and for every custom
    role that read wazuh-alerts-*: an added entry on the findings name space with its DLS rewritten, or a flag."""
    pw = idx_password5()
    rest = os.path.join(bundle, "indexer-security", "rest")
    shipped = os.path.join(bundle, "indexer-security", "shipped")
    users_yml = open(os.path.join(bundle, "indexer-security", "backup", "internal_users.yml")).read()
    failed, report = 0, {"translated": [], "flagged": [], "stock_mapping_additions": []}
    code, roles5 = idx("GET", "/_plugins/_security/api/roles", pw)
    order = [("actiongroups", ("allowed_actions", "type", "description")),
             ("tenants", ("description",)),
             ("roles", ("cluster_permissions", "index_permissions", "tenant_permissions", "description")),
             ("internalusers", ("backend_roles", "attributes", "description", "opendistro_security_roles")),
             ("rolesmapping", ("backend_roles", "hosts", "users", "and_backend_roles", "description"))]
    for kind, fields in order:
        objs = custom(json.load(open(os.path.join(rest, kind + ".json"))), shipped_names(shipped, kind))
        for name, o in sorted(objs.items()):
            body = {f: o[f] for f in fields if f in o and o[f] not in (None, "")}
            if kind == "roles":
                extra = []
                for ip in body.get("index_permissions", []):
                    if not any(re.match(r"^wazuh-alerts", p) or p in ("wazuh-*", "*") for p in ip.get("index_patterns", [])):
                        continue
                    new = {"index_patterns": ["wazuh-findings-v5*"], "allowed_actions": ip.get("allowed_actions", ["read"]),
                           "fls": ip.get("fls", []), "masked_fields": ip.get("masked_fields", [])}
                    if ip.get("dls"):
                        ndls, unknown = translate_dls(ip["dls"])
                        if unknown:
                            report["flagged"].append({"role": name, "reason": "document-level security uses 4.x fields with no 5.0 equivalent in the tool's table",
                                                      "fields": unknown, "dls": ip["dls"], "action": "NOT granted on the findings name space"})
                            continue
                        new["dls"] = ndls
                    if ip.get("fls"):
                        report["flagged"].append({"role": name, "reason": "field-level security is written for 4.x field names; the original alert is also kept under legacy.alert.*",
                                                  "fls": ip["fls"], "action": "NOT granted on the findings name space"})
                        continue
                    extra.append(new)
                    report["translated"].append({"role": name, "from": ip.get("index_patterns"), "to": new["index_patterns"],
                                                 "dls_4x": ip.get("dls"), "dls_5x": new.get("dls")})
                body["index_permissions"] = body.get("index_permissions", []) + extra
            if kind == "internalusers":
                m = re.search(r"^%s:\n(?:[ \t]+.*\n)*?[ \t]+hash:[ \t]*\"?([^\"\n]+)\"?" % re.escape(name), users_yml, re.M)
                if not m:
                    print(f"import-security: {kind}/{name}: no hash in the backup, skipped")
                    failed += 1
                    continue
                body["hash"] = m.group(1)
            code, d = idx("PUT", f"/_plugins/_security/api/{kind}/{urllib.parse.quote(name)}", pw, body=body)
            print(f"import-security: PUT {kind}/{name}: HTTP {code} {json.dumps(d)[:200]}")
            failed += code not in (200, 201)
    # users a site added to a stock role mapping (for example a dashboard user in kibana_user)
    sm = shipped_mapping_users(shipped)
    maps4 = json.load(open(os.path.join(rest, "rolesmapping.json")))
    code, maps5 = idx("GET", "/_plugins/_security/api/rolesmapping", pw)
    for role, v in sorted(maps4.items()):
        if not isinstance(v, dict) or role not in sm:
            continue
        added = sorted(set(v.get("users", [])) - set(sm.get(role, [])))
        if not added:
            continue
        if not isinstance(roles5, dict) or role not in roles5:
            report["flagged"].append({"role": role, "reason": "users were added to this stock 4.x mapping, and 5.0 has no role of that name", "users": added})
            continue
        cur = (maps5 or {}).get(role, {}) if isinstance(maps5, dict) else {}
        body = {"users": sorted(set(cur.get("users", [])) | set(added)), "backend_roles": cur.get("backend_roles", []),
                "hosts": cur.get("hosts", []), "and_backend_roles": cur.get("and_backend_roles", [])}
        code, d = idx("PUT", f"/_plugins/_security/api/rolesmapping/{urllib.parse.quote(role)}", pw, body=body)
        print(f"import-security: stock mapping {role}: added users {added}: HTTP {code} {json.dumps(d)[:160]}")
        report["stock_mapping_additions"].append({"role": role, "users": added, "http": code})
        failed += code not in (200, 201)
    write(os.path.join(bundle, "indexer-security"), "import-report.json", report)
    for t in report["translated"]:
        print(f"import-security: role {t['role']}: {t['from']} also granted as {t['to']}; DLS {t['dls_4x']} -> {t['dls_5x']}")
    for f in report["flagged"]:
        print(f"import-security: FLAGGED {json.dumps(f)}")
    return 1 if failed else 0


# the custom 4.x dashboards read the history through its two aliases, with ONE wildcard. The former title named
# both index families ("wazuh-legacy-4x-alerts-*,wazuh-legacy-4x-cloud-*"); when a migration has no cloud alerts (or
# retention later deletes the last cloud month) the cloud element matches nothing, the dashboard's field list request
# answers 404 "No indices match pattern" and every panel fails. A single wildcard resolves while either family
# exists, and through the aliases it follows the history's on/off switch like the stock modules do.
HISTORY_PATTERN = "wazuh-findings-v5*-legacy-4x"


def import_saved_objects(ndjson):
    """A 4.x dashboard is built on 4.x field names. It is imported as a view of the migrated history: the 4.x index
    pattern points at the history indices and every field is read under legacy.alert.* (the preserved alert)."""
    pw = idx_password5()
    dash = os.environ.get("MIG_DASH5_URL", "https://127.0.0.1:443")
    # refuse before writing when the title would resolve to nothing (history not switched on yet, or no history)
    code, al = idx("GET", "/_cat/aliases/" + HISTORY_PATTERN + "?format=json&h=alias,index", pw)
    if code != 200 or not al:
        print(f"import-saved-objects: no history alias matches {HISTORY_PATTERN} (HTTP {code}): switch the history on first; nothing imported")
        return 1
    out = []
    stock = {o["id"] for o in (saved_objects(os.environ.get("MIG_DASH5_URL", "https://127.0.0.1:443"), "admin", pw) or []) if isinstance(o, dict)}
    # Rule 20: the tool records, per object it writes, each attribute it changed with the
    # value before and the value written; a rollback resets only those, and only where nobody changed them since. It never
    # overwrites an object that exists on 5.0 (the import runs without overwrite), so no admin edit is replaced wholesale.
    ledger_p = os.path.join(os.path.dirname(os.path.abspath(ndjson)), "saved-objects-ledger.json")
    ledger = load(os.path.dirname(ledger_p), os.path.basename(ledger_p)) or {}

    def pre(field):
        return field if field.startswith(("legacy.", "_")) else "legacy.alert." + field

    def fix_query(s):
        # kuery / lucene: prefix every `field:` token
        # also KQL range expressions (`rule.level >= 10`); the field:value form alone left them on 4.x names (0 hits)
        return re.sub(r"(?<![\w.])([A-Za-z_@][\w.@]*)(\s*)(:|>=|<=|>|<)", lambda m: (m.group(1) if m.group(1) in ("http", "https") else pre(m.group(1))) + m.group(2) + m.group(3), s)

    def fix_search_source(js):
        try:
            d = json.loads(js)
        except ValueError:
            return js
        q = d.get("query")
        if isinstance(q, dict) and isinstance(q.get("query"), str) and q["query"]:
            q["query"] = fix_query(q["query"])
        return json.dumps(d)
    n = {"index-pattern": 0, "rewritten": 0, "skipped_stock": 0}
    for line in open(ndjson):
        if not line.strip():
            continue
        o = json.loads(line)
        if "exportedCount" in o:
            continue
        at = o.get("attributes", {})
        before = json.loads(json.dumps(at))
        key = "%s/%s" % (o.get("type"), o.get("id"))
        if o.get("id") in stock:     # exists on 5.0: stock, an earlier run's (in the ledger) or someone else's; never overwritten
            n["skipped_stock"] += 1
            print(f"import-saved-objects: {key} exists on 5.0 ({'written by an earlier run' if key in ledger else 'not the tool’s'}): not overwritten")
            continue
        if o.get("type") == "index-pattern":
            title = at.get("title", "")
            if re.match(r"wazuh-alerts", title):
                at["title"] = HISTORY_PATTERN
                at["timeFieldName"] = "@timestamp"
                at.pop("fields", None)
                n["index-pattern"] += 1
                print(f"import-saved-objects: index pattern {o['id']}: title '{title}' -> '{HISTORY_PATTERN}', time field @timestamp")
            else:
                n["skipped_stock"] += 1
                continue    # monitoring, statistics, states: nothing of them is migrated
        elif o.get("type") in ("visualization", "search", "dashboard"):
            if o["id"] in stock:
                n["skipped_stock"] += 1
                continue
            if "visState" in at:
                at["visState"] = re.sub(r'("field"\s*:\s*")([^"]+)(")', lambda m: m.group(1) + pre(m.group(2)) + m.group(3), at["visState"])
            ksm = at.get("kibanaSavedObjectMeta", {})
            if "searchSourceJSON" in ksm:
                ksm["searchSourceJSON"] = fix_search_source(ksm["searchSourceJSON"])
            if o["type"] == "search" and "columns" in at:
                at["columns"] = [pre(c) if c != "_source" else c for c in at["columns"]]
            if o["type"] == "search" and at.get("sort"):  # the sort field too (4.x `timestamp`)
                at["sort"] = [[pre(x[0])] + list(x[1:]) if isinstance(x, list) and x else x for x in at["sort"]]
            n["rewritten"] += 1
        changed = {}
        for k in TOOL_ATTRS.get(o.get("type"), ()):
            b_, w_ = _attr(before, k), _attr(at, k)
            if b_ != w_ and w_ is not _ABSENT:
                changed[k] = {"before": None if b_ is _ABSENT else b_, "before_absent": b_ is _ABSENT, "written": w_}
        ledger[key] = {"type": o.get("type"), "id": o.get("id"), "created": True, "attributes": changed}
        out.append(json.dumps(o))
    payload = ("\n".join(out) + "\n").encode()
    boundary = "----mige1" + sha(payload)[:16]
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"v4.ndjson\"\r\n"
            f"Content-Type: application/ndjson\r\n\r\n").encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    write(os.path.dirname(ledger_p), os.path.basename(ledger_p), ledger)   # before the import: a kill after it still leaves the record
    code, raw = http("POST", os.environ.get("MIG_DASH5_URL", "https://127.0.0.1:443") + "/api/saved_objects/_import", user="admin", password=pw, body=body,
                     headers={"osd-xsrf": "true", "Content-Type": "multipart/form-data; boundary=" + boundary})
    print(f"import-saved-objects: {json.dumps(n)}; HTTP {code} {raw.decode(errors='replace')[:900]}")
    try:
        d = json.loads(raw)
    except ValueError:
        return 1
    if not (code == 200 and d.get("success")):
        return 1
    # an import that succeeds is not a dashboard that works (F6 reported success over a pattern that answered 404):
    # ask the dashboard for the field list of the retitled pattern, as the browser will.
    q = urllib.parse.urlencode([("pattern", HISTORY_PATTERN), ("meta_fields", "_source"), ("meta_fields", "_id")])
    fcode, fraw = http("GET", dash + "/api/index_patterns/_fields_for_wildcard?" + q, user="admin", password=pw, headers={"osd-xsrf": "true"})
    try:
        nf = len(json.loads(fraw).get("fields", []))
    except ValueError:
        nf = 0
    print(f"import-saved-objects: field list of {HISTORY_PATTERN}: HTTP {fcode}, {nf} field(s)")
    return 0 if fcode == 200 and nf else 1


# the attributes the dashboard step rewrites, per type (rule 20: these and only these are ever reset)
TOOL_ATTRS = {"index-pattern": ("title", "timeFieldName"),
              "visualization": ("visState", "kibanaSavedObjectMeta.searchSourceJSON"),
              "search": ("columns", "sort", "kibanaSavedObjectMeta.searchSourceJSON"),
              "dashboard": ("kibanaSavedObjectMeta.searchSourceJSON",)}
_ABSENT = object()


def _attr(attrs, dotted):
    cur = attrs
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _ABSENT
        cur = cur[part]
    return cur


def _partial(dotted, value):
    """{"a": {"b": value}} for "a.b": a saved-object update merges attributes, so siblings are left as they are."""
    parts = dotted.split(".")
    out = value
    for part in reversed(parts):
        out = {part: out}
    return out


def rollback_saved_objects(ledger_path, dry_run=""):
    """Rule 20: reset only the attributes the tool changed, each to its value before the tool, and only where the object
    still holds what the tool wrote (S5: a whole-object restore discarded an administrator's later edit; a title-only reset
    kept it). Never a whole saved copy, never overwrite=true, never a delete."""
    pw = idx_password5()
    dash = os.environ.get("MIG_DASH5_URL", "https://127.0.0.1:443")
    ledger = load(os.path.dirname(os.path.abspath(ledger_path)), os.path.basename(ledger_path)) or {}
    reset, kept, gone = [], [], []
    for key, e in sorted(ledger.items()):
        code, cur = jget("GET", "%s/api/saved_objects/%s/%s" % (dash, e["type"], urllib.parse.quote(e["id"], safe="")),
                         user="admin", password=pw, headers={"osd-xsrf": "true"})
        if code == 404:
            gone.append(key)
            continue
        if code != 200:
            print("rollback-saved-objects: %s: HTTP %s: cannot read it, nothing changed" % (key, code))
            return 1
        attrs = (cur or {}).get("attributes", {})
        patch = {}
        for k, ch in sorted(e.get("attributes", {}).items()):
            if _attr(attrs, k) != ch["written"]:
                kept.append("%s %s (changed since the tool wrote it)" % (key, k))
                continue
            if ch.get("before_absent"):
                kept.append("%s %s (it had no value before the tool; left)" % (key, k))
                continue
            p = _partial(k, ch["before"])
            for top, v in p.items():
                if isinstance(v, dict) and isinstance(patch.get(top), dict):
                    patch[top].update(v)
                else:
                    patch[top] = v
            reset.append("%s %s" % (key, k))
        if patch and not dry_run:
            code, r = jget("PUT", "%s/api/saved_objects/%s/%s" % (dash, e["type"], urllib.parse.quote(e["id"], safe="")),
                           user="admin", password=pw, body={"attributes": patch}, headers={"osd-xsrf": "true"})
            if code != 200:
                print("rollback-saved-objects: %s: reset refused: HTTP %s %s" % (key, code, json.dumps(r)[:300]))
                return 1
    print("rollback-saved-objects: reset %d attribute(s): %s" % (len(reset), reset))
    print("rollback-saved-objects: left as they are: %s; objects gone: %s" % (kept or "none", gone or "none"))
    return 0


def policy_unclassified(action=""):
    """policy-unclassified get|on|off|keep: raw indexing of unclassified events in the standard policy. keep: read it and
    switch it on when it is off (the finish's keep-raw answer). Any other word is refused: an unknown action switched raw
    indexing off."""
    if action not in ("get", "on", "off", "keep"):
        print("policy-unclassified: unknown action %r (get, on, off or keep): nothing changed" % action)
        return 2
    pw = idx_password5()
    code, d = idx("POST", "/wazuh-threatintel-policies/_search?size=10", pw, body={"query": {"term": {"space.name": "standard"}}})
    hits = d.get("hits", {}).get("hits", []) if code == 200 else []
    if not hits:
        print(f"policy-unclassified: no standard policy found (HTTP {code})")
        return 1
    doc = hits[0]["_source"]["document"]
    print(f"policy-unclassified: standard space: index_unclassified_events={doc.get('index_unclassified_events')} index_discarded_events={doc.get('index_discarded_events')} enabled={doc.get('enabled')}")
    if action == "get":
        return 0
    if action == "keep":
        if doc.get("index_unclassified_events") is True:
            print("policy-unclassified: raw indexing is on (read back): kept")
            return 0
        print("policy-unclassified: raw indexing was OFF although the answer keeps it on: switched on again")
        action = "on"
    body = {"resource": {"enabled": doc.get("enabled", True), "index_unclassified_events": action == "on",
                         "index_discarded_events": doc.get("index_discarded_events", False)}}
    code, d = idx("PUT", "/_plugins/_content_manager/policy/standard", pw, body=body)
    print(f"policy-unclassified: PUT policy/standard index_unclassified_events={action == 'on'}: HTTP {code} {json.dumps(d)[:300]}")
    return 0 if code == 200 else 1


def use_password(conf):
    """E5 fold: <auth><use_password> of a manager configuration ("yes", "no"), None when not readable."""
    try:
        t = open(conf, errors="replace").read()
    except OSError:
        return None
    m = re.search(r"<auth>.*?<use_password>\s*([^<\s]+)\s*</use_password>.*?</auth>", t, re.S)
    return m.group(1) if m else None


def enrollment_off_row(e5):
    """The phase 8 row for a 4.x source that enrolled without a password: what 5.0 does, and how to turn a password on."""
    if e5.get("use_password") == "no":
        return ("4.x enrolled without a password; 5.0 too (use_password no, carried by the settings stage). To require one: "
                "use_password yes in <auth> of /etc/wazuh-manager/wazuh-manager.conf, the password in "
                "/etc/wazuh-manager/authd.pass (the one the 5.0 install generated, %s, or your own of 16 or more characters), "
                "restart wazuh-manager; 5.0 agents enroll with tokens: mint them with a credential (wazuh-manager-authd "
                "--create-enrollment-token, without --no-credential), as tokens made with --no-credential stop working"
                % ("present" if e5.get("authd_pass_sha256") else "none found"))
    if e5.get("use_password") == "yes":
        return ("4.x enrolled without a password; 5.0 requires the one in /etc/wazuh-manager/authd.pass (%s): 5.0 agents that "
                "enroll from now on need an enrollment token minted with a credential (wazuh-manager-authd --create-enrollment-token, "
                "without --no-credential), 4.x agents on 1515 the password" % ("present" if e5.get("authd_pass_sha256") else "NONE FOUND: no agent can enroll"))
    return "4.x enrolled without a password; 5.0's use_password could not be read (authd.pass %s)" % (
        "present" if e5.get("authd_pass_sha256") else "none found")


def truth5(outdir):
    api = Api(api_password5())
    ipw = idx_password5()
    agents = api.get("/agents?select=id,name,status,version,group,ip,registerIP,os.name,os.platform,dateAdd,lastKeepAlive&limit=100000")
    write(outdir, "agents.json", agents)
    write(outdir, "client_keys.json", client_keys(M5ETC + "/client.keys"))
    write(outdir, "group_files.json", group_dirs(M5ETC + "/shared"))
    write(outdir, "groups_api.json", api.get("/groups?limit=100000"))
    write(outdir, "api_security.json", {k: api.get(f"/security/{k}?limit=500") for k in ("users", "roles", "policies", "rules")})
    p = M5ETC + "/authd.pass"
    write(outdir, "enrollment.json", {"authd_pass_sha256": fsha(p),
                                       "authd_pass_bytes": len(open(p, "rb").read().strip()) if os.path.exists(p) else None,
                                       "use_password": use_password(M5ETC + "/wazuh-manager.conf")})
    sec = security_objects(ipw)
    isec = {k: sorted(custom(v)) if "_error" not in v else v for k, v in sec.items()}
    isec["mapping_users"] = {r: v.get("users", []) for r, v in (sec.get("rolesmapping") or {}).items() if isinstance(v, dict) and v.get("users")}
    write(outdir, "indexer_security.json", isec)
    write(outdir, "saved_objects.json", saved_objects("https://127.0.0.1:443", "admin", ipw))
    write(outdir, "indices.json", indices(ipw, "*"))
    code, d = idx("POST", "/wazuh-legacy-4x-*/_search?size=0&ignore_unavailable=true", ipw, body={
        "track_total_hits": True, "aggs": {"i": {"terms": {"field": "legacy.index", "size": 20000}}}})
    write(outdir, "history.json", {"total": d["hits"]["total"]["value"], "per_source_index": {b["key"]: b["doc_count"] for b in d["aggregations"]["i"]["buckets"]}}
          if code == 200 and "aggregations" in d else {"_error": code, "total": 0, "per_source_index": {}})
    code, d = idx("POST", "/wazuh-findings-v5*/_search?size=0&ignore_unavailable=true", ipw, body={
        "track_total_hits": True, "query": {"term": {"tags": "v4-legacy"}}})
    write(outdir, "history_visible.json", {"through_findings_pattern": d.get("hits", {}).get("total", {}).get("value") if code == 200 else None})
    code, d = idx("GET", "/_cat/aliases/wazuh-findings-v5*legacy*?format=json&h=alias,index", ipw)
    write(outdir, "history_aliases.json", d if code == 200 else {"_error": code})
    code, d = idx("POST", "/wazuh-events-v5-*/_search?size=0&ignore_unavailable=true", ipw, body={
        "track_total_hits": True,
        "aggs": {"agents": {"terms": {"field": "wazuh.agent.id", "size": 1000},
                            "aggs": {"last": {"max": {"field": "@timestamp"}}, "first": {"min": {"field": "@timestamp"}}}}}})
    write(outdir, "events.json", {"total": d["hits"]["total"]["value"],
                                  "per_agent": {b["key"]: {"count": b["doc_count"], "first": b["first"].get("value_as_string"), "last": b["last"].get("value_as_string")}
                                                for b in d.get("aggregations", {}).get("agents", {}).get("buckets", [])}}
          if code == 200 else {"_error": code})
    write(outdir, "taken.json", {"at": now_iso()})
    print(f"truth5: {len(agents) if isinstance(agents, list) else agents} agent(s), written to {outdir}")


def pre_upgrade_confs(bundle):
    """E2 fold (reconciled): {group: agent.conf the settings stage's pre-upgrade pass
    uploaded}, from its record settings/groups-pre/uploaded.json (settings_stage.py record_upload): exact group names,
    only files that were uploaded."""
    p = os.path.join(bundle, "settings", "groups-pre", "uploaded.json")
    try:
        d = json.load(open(p))
    except (OSError, ValueError):
        return {}
    return {g: os.path.join(os.path.dirname(p), v["agent_conf"]) for g, v in d.items() if isinstance(v, dict) and v.get("agent_conf")}


def expired_months(fp):
    """E4-deb N-H1: the months the history load left out on purpose (the retention had already expired them when the
    load decided, or deleted them after it), from the load's journal (history_load.py Journal: HIST/load-state/
    journal.json beside the fingerprint, or HISTORY_JOURNAL). {month "YYYY.MM": reason}."""
    jp = os.environ.get("HISTORY_JOURNAL") or os.path.join(os.path.dirname(os.path.abspath(fp)), "history", "load-state", "journal.json")
    try:
        months = json.load(open(jp)).get("months", {})
    except (OSError, ValueError):
        return {}
    out = {}
    for k, e in months.items():
        if e.get("status") == "expired-before-load":
            out[k] = "expired by the retention before the load"
        elif e.get("deleted_by_retention"):
            out[k] = "deleted by the retention after the load"
    return out


def history_rows(fp, t5, pending, x4=None):
    """The history lines of compare: documents per 4.x index against legacy.index on 5.0, and visible through the
    findings pattern. E4-deb N-H1: the months the retention left out are their own line, NOT LOADED (retention), not
    counted as LOST (before, the history phase's last step failed on every source holding months past its retention)."""
    rows = []
    row = lambda item, ok, detail: rows.append((item, "CARRIED" if ok is True else "LOST" if ok is False else str(ok), detail))
    x4 = x4 if x4 is not None else load(fp, "indices.json")
    hist4 = {k: v for k, v in x4.items() if re.match(r"wazuh-alerts-4\.x-", k) and v}
    exp = expired_months(fp)
    mon = lambda k: (lambda m: "%s.%s" % (m.group(1), m.group(2)) if m else None)(re.search(r"(\d{4})\.(\d{2})\.\d{2}$", k))
    left = {k: v for k, v in hist4.items() if mon(k) in exp}
    hist4 = {k: v for k, v in hist4.items() if k not in left}
    h5 = load(t5, "history.json") or {}
    hist5 = {k: v for k, v in h5.get("per_source_index", {}).items() if k not in left}
    # with the history loaded after the opening, the verify phase runs before the load: these lines are PENDING
    # there (HISTORY_PENDING=1) and the history phase compares again with them counted.
    row("alert history: documents per 4.x index (fingerprint against legacy.index on 5.0)", "PENDING" if pending and hist4 != hist5 else hist4 == hist5,
        f"{sum(hist4.values())} alert(s) in {len(hist4)} index(es) at the freeze, {sum(hist5.values())} in {len(hist5)} on 5.0"
        + ("" if hist4 == hist5 else f"; differing: {sorted(k for k in set(hist4) | set(hist5) if hist4.get(k) != hist5.get(k))[:6]}")
        + ("; loaded after the opening (history phase)" if pending else ""))
    if left:
        ms = sorted({mon(k) for k in left})
        row("alert history: months the 4.x retention left out", "NOT LOADED (retention)",
            f"{sum(left.values())} alert(s) in {len(left)} index(es) of {', '.join(ms)}: " + "; ".join(sorted({exp[m] for m in ms})))
    vis = (load(t5, "history_visible.json") or {}).get("through_findings_pattern")
    row("alert history: visible through wazuh-findings-v5* (aliases on)", "PENDING" if pending and vis != sum(hist4.values()) else vis == sum(hist4.values()),
        f"{vis} of {sum(hist4.values())}" + (" (the months the retention left out not counted)" if left else "")
        + ("; switched on after its proof (history phase)" if pending else ""))
    return rows


def compare(t4, fp, t5):
    rows = []
    cleaned = {g: norm_sha(f) for g, f in pre_upgrade_confs(os.path.dirname(os.path.abspath(fp))).items()}   # E2 fold

    def row(item, ok, detail):
        rows.append((item, "CARRIED" if ok is True else "LOST" if ok is False else str(ok), detail))

    a4 = {a["id"]: a for a in load(fp, "agents.json") if a["id"] != "000"}
    live4 = {a["id"]: a for a in (load(t4, "agents.json") or []) if a["id"] != "000"}
    a5 = {a["id"]: a for a in (load(t5, "agents.json") or []) if isinstance(a, dict)}
    same_src = {i: (a["name"], a.get("group")) for i, a in a4.items()} == {i: (a["name"], a.get("group")) for i, a in live4.items()}
    row("source: registry at the freeze equals the registry while live", True if same_src else "CHANGED",
        "fingerprint and pre-copy truth agree" if same_src else "the registry changed between the pre-copy and the freeze; the fingerprint is what counts")
    row("agents: ids and names", {i: a["name"] for i, a in a4.items()} == {i: a["name"] for i, a in a5.items()},
        f"4.x {sorted((i, a['name']) for i, a in a4.items())} / 5.0 {sorted((i, a['name']) for i, a in a5.items())}")
    row("agent 000 (the manager's own host)", "REMOVED" if "000" not in a5 else True, "5.0 has no agent 000")
    k4, k5 = load(fp, "client_keys.json"), load(t5, "client_keys.json") or {}
    row("agent keys (sha256 of each key)", k4 == k5, f"{len(k4)} key(s) on 4.x, {len(k5)} on 5.0, identical={k4 == k5}")
    g4 = {i: a.get("group", []) or ["default"] for i, a in a4.items()}
    g5 = {i: a.get("group", []) for i, a in a5.items()}
    row("group membership, in order", g4 == g5, f"4.x {g4} / 5.0 {g5}")
    f4, f5 = load(fp, "group_files.json"), load(t5, "group_files.json") or {}
    for g in sorted(f4):
        if g == "default":
            only4 = sorted(set(f4[g]) - set(f5.get(g, {})))
            row("group default: agent.conf", "CHANGED" if f4[g].get("agent.conf") != f5.get(g, {}).get("agent.conf") else True,
                "5.0 keeps its own; the import appends the 4.x one when it sets anything")
            row("group default: rootcheck and audit files", True if not only4 else "NOT CARRIED",
                f"{len(only4)} 4.x file(s) not in 5.0 (4.x agents lose rootcheck signatures): {only4[:3]}{'...' if len(only4) > 3 else ''}")
            continue
        conf_same = f4[g].get("agent.conf") == f5.get(g, {}).get("agent.conf")
        if not conf_same and cleaned.get(g) and cleaned[g] == f5.get(g, {}).get("agent.conf"):
            # the pre-upgrade pass removed what a 4.x agent or the 5.0 API refuses
            # (prefilter_cmd) on purpose; 5.0 holds exactly what it uploaded. Any other content stays LOST.
            row(f"group {g}: agent.conf (compared without indentation)", "CLEANED",
                "as the pre-upgrade group pass uploaded it (options a 4.x agent or the 5.0 API refuses removed; see settings/groups-pre/)")
        else:
            row(f"group {g}: agent.conf (compared without indentation)", conf_same, "same content" if conf_same else "content differs or missing")
        others4 = {k: v for k, v in f4[g].items() if k != "agent.conf"}
        for k, v in sorted(others4.items()):
            there = f5.get(g, {}).get(k) == v
            sca = k.endswith((".yml", ".yaml"))
            row(f"group {g}: file {k}", there if sca else (True if there else "NOT CARRIED"),
                ("SCA policy loaded by agent.conf" if sca else "extra file in the group folder: the identity tool reports it and leaves it behind") + (", present" if there else ", absent on 5.0"))
    s4, s5 = load(t4, "api_security.json"), load(t5, "api_security.json") or {}
    for kind, key in (("users", "username"), ("roles", "name"), ("policies", "name"), ("rules", "name")):
        c4 = sorted(o[key] for o in s4[kind] if o["id"] >= 100)
        c5 = sorted(o[key] for o in s5.get(kind, []) if isinstance(o, dict) and o["id"] >= 100) if isinstance(s5.get(kind), list) else s5.get(kind)
        row(f"Server API custom {kind}", c4 == c5, f"4.x {c4} / 5.0 {c5}")
    u4 = {o["username"]: sorted(o.get("roles", [])) for o in s4["users"]}
    u5 = {o["username"]: sorted(o.get("roles", [])) for o in s5.get("users", []) if isinstance(o, dict)} if isinstance(s5.get("users"), list) else {}
    row("Server API default users", "RENAMED" if "wazuh-wui" in u4 and "wazuh-internal-client" in u5 else sorted(u4) == sorted(u5),
        f"4.x {sorted(u4)} / 5.0 {sorted(u5)}")
    e4, e5 = load(fp, "enrollment.json"), load(t5, "enrollment.json") or {}
    if e4.get("authd_pass_sha256") is None:
        # a 4.x source that enrolls without a password has nothing to carry; 5.0 generates its own
        # (assess says so). Reporting it LOST failed phase 8 on every such source.
        row("enrollment password", "NOT USED ON 4.x", enrollment_off_row(e5))
    else:
        row("enrollment password", e4["authd_pass_sha256"] == e5.get("authd_pass_sha256"), f"{e4['authd_pass_bytes']} bytes on 4.x; same file on 5.0: {e4['authd_pass_sha256'] == e5.get('authd_pass_sha256')}")
    i4, i5 = load(fp, "indexer_security.json"), load(t5, "indexer_security.json") or {}
    for kind in ("internalusers", "roles", "rolesmapping"):
        want = i4[kind]
        have = [n for n in want if n in (i5.get(kind) or [])]
        row(f"indexer custom {kind}", want == have, f"4.x {want} / present on 5.0 {have}")
    add4 = i4.get("stock_mapping_additions", {})
    mu5 = i5.get("mapping_users", {})
    okadd = all(set(u) <= set(mu5.get(r, [])) for r, u in add4.items())
    row("indexer: users added to stock role mappings", okadd if add4 else True, f"4.x {add4} / 5.0 users of those mappings { {r: mu5.get(r) for r in add4} }")
    o4, o5 = load(fp, "saved_objects.json"), load(t5, "saved_objects.json") or []
    want = [(o["type"], o["id"]) for o in o4 if o["type"] in ("dashboard", "visualization", "search")]
    have5 = {(o["type"], o["id"]) for o in o5} if isinstance(o5, list) else set()
    # E2 fold (E2-rpm fix 04 = E2-deb fix 2): with HISTORY_LOAD=after-open the custom dashboards are imported in the
    # history phase, after the aliases are on (merge conflict C6): PENDING in phase 8, as the two history lines, or phase 8
    # fails for every site with a custom dashboard and the run never reaches the history phase.
    dash_ok = all(w in have5 for w in want)
    dash_pending = os.environ.get("HISTORY_PENDING") == "1" and not dash_ok
    row("custom dashboards, visualizations, searches", "PENDING" if dash_pending else dash_ok,
        f"4.x {want} / present on 5.0 {[w for w in want if w in have5]}" + ("; imported after the history is on (history phase)" if dash_pending else ""))
    x4 = load(fp, "indices.json")
    for r in history_rows(fp, t5, os.environ.get("HISTORY_PENDING") == "1", x4):
        rows.append(r)
    other = sorted(k for k, v in x4.items() if not re.match(r"wazuh-alerts-4\.x-", k) and v)
    row("other 4.x indices (vulnerability state, monitoring, statistics)", "NOT CARRIED", f"{other}: rebuilt by 5.0 from the agents, not migrated")
    ms = load(fp, "manager_settings.json")
    if os.environ.get("SETTINGS_CARRIED") == "1":   # the settings stage carried them (phase 6)
        row("manager settings (ossec.conf, internal options)", "CONVERTED",
            f"4.x blocks {ms['ossec_conf_blocks']}, internal options {ms['local_internal_options']}: converted and merged into the installed 5.0 files "
            "by the settings stage (what was kept, replaced or dropped: settings/candidate/ report, results/import.settings.log)")
    else:
        row("manager settings (ossec.conf, internal options)", "NOT CARRIED",
            f"4.x blocks {ms['ossec_conf_blocks']}, internal options {ms['local_internal_options']}: see the settings converter")
    ev = load(t5, "events.json") or {}
    st = {i: a.get("status") for i, a in a5.items()}
    away = sorted(i for i, a in live4.items() if a["status"] == "active" and st.get(i) != "active")
    if away and os.environ.get("VERIFY_AGAIN") == "1":
        # E7-aio U9: the first verification saw these agents active on 5.0 (it passed); one stopped since is not a lost
        # migration: it keeps its key and group, and the agents phase upgrades it once it connects again
        row("agents active on 5.0", "AWAY", "active at the first verification, not connected now: %s (they keep their keys and groups; "
            "each is upgraded once it connects again); status %s" % (", ".join("%s %s" % (i, a5.get(i, {}).get("name", "")) for i in away), st))
    else:
        row("agents active on 5.0", not away, f"status {st}; events per agent {ev.get('per_agent')}")
    w = max(len(r[0]) for r in rows)
    bad = 0
    for item, verdict, detail in rows:
        print(f"{item.ljust(w)}  {verdict.ljust(11)}  {detail}")
        bad += verdict == "LOST"
    print(f"compare: {len(rows)} line(s), {bad} LOST")
    return 1 if bad else 0


def wait_agents(t4, secs, opened):
    """'active' alone is not enough: the status of an agent that left stays active for minutes. Count a keepalive newer than the opening.
    Which agents to wait for comes from the truth taken while 4.x was live (the frozen registry no longer says who was connected)."""
    want = sorted(a["id"] for a in load(t4, "agents.json") if a["id"] != "000" and a["status"] == "active")
    end = time.time() + int(secs)
    seen = {}
    while time.time() < end:
        try:
            api = Api(api_password5())
            st = {a["id"]: a for a in api.get("/agents?select=id,status,lastKeepAlive,version&limit=100000")}
        except SystemExit as e:
            st = {}
            print(f"wait-agents: {e}", flush=True)
        for i in want:
            a = st.get(i, {})
            ka = (a.get("lastKeepAlive") or "").replace("+00:00", "Z")
            if a.get("status") == "active" and ka >= opened and i not in seen:
                seen[i] = ka
                print(f"wait-agents: agent {i} active, keepalive {ka} (listeners opened {opened}), version {a.get('version')}", flush=True)
        if len(seen) == len(want):
            print(f"wait-agents: all {len(want)} agent(s) that were active on 4.x sent a keepalive after the opening")
            return 0
        time.sleep(5)
    print(f"wait-agents: timeout after {secs}s; seen {sorted(seen)} of {want}")
    return 1




def settle_agents(t4, secs="120", _sleep=time.sleep, _now=time.time):
    """E4-rpm gap 3: phase 8 read the Windows agent's status 1 s before it was back from "Agent is reloading due to shared
    configuration changes" (16 s after it connected) and failed, 2 of 2 runs; a rerun passed. Before the comparison
    reads the agents, wait (bounded, default 120 s) while an agent that was active on 4.x is not active on 5.0, naming
    it; then the comparison judges as before. Always exit 0: the verdict is the comparison's."""
    want = sorted(a["id"] for a in load(t4, "agents.json") or [] if a["id"] != "000" and a.get("status") == "active")
    end, said = _now() + int(secs), set()
    while True:
        try:
            st = {a["id"]: a.get("status") for a in Api(api_password5()).get("/agents?select=id,status&limit=100000")}
        except SystemExit as e:
            print("settle-agents: %s" % e, flush=True)
            st = {}
        late = [i for i in want if st.get(i) != "active"]
        if not late:
            print("settle-agents: every agent that was active on 4.x is active on 5.0%s" % (
                " (waited for %s)" % " ".join(sorted(said)) if said else ""), flush=True)
            return 0
        if _now() >= end:
            print("settle-agents: after %ss still not active: %s (the comparison judges them)" % (secs, " ".join(
                "%s (%s)" % (i, st.get(i) or "absent") for i in late)), flush=True)
            return 0
        for i in late:
            if i not in said:
                print("settle-agents: agent %s is %s (reconnecting, or reloading its new group files): waiting up to %ss" % (
                    i, st.get(i) or "absent", secs), flush=True)
                said.add(i)
        _sleep(5)


def agent_registry(bundle, out):
    """H1/C23: the 4.x registry for the history's group stamp, {"agents": {id: {"name", "groups"}}}, from the frozen
    fingerprint (global.db at the freeze). The loader stamps an alert only where the agent id AND name match (C23: 7,995
    alerts of sample or reused ids would otherwise get the wrong groups); membership is the migration day's."""
    agents = load(os.path.join(bundle, "fingerprint"), "agents.json") or []
    reg = {"source": "4.x global.db at the freeze (fingerprint/agents.json)",
           "agents": {a["id"]: {"name": a["name"], "groups": list(a.get("group") or [])} for a in agents}}
    write(os.path.dirname(out) or ".", os.path.basename(out), reg)
    print(f"agent-registry: {len(reg['agents'])} agent(s) written to {out}")
    return 0



# ------------------------------------------------------------------------------- OF1: the 4.x retention (decision 5b)
ALERT_SAMPLES = ("wazuh-alerts-4.x-2025.01.01", "wazuh-alerts-4.x-2026.12.31")
_UNIT_S = {"d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}


def _age_days(v):
    """An OpenSearch time value (90d, 2160h, 30m...) in whole days, rounded up; None when it is not one."""
    m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(d|h|m|s|ms)\s*", str(v or ""))
    if not m:
        return None
    sec = float(m.group(1)) * _UNIT_S[m.group(2)]
    return int(-(-sec // 86400)) if sec > 0 else 0


def ism_delete_age(policy):
    """Days after which this ISM policy deletes an index: the min_index_age of a transition into a state that deletes
    (counted from the index's creation, as the migrated monthly indices count from their newest day). The longest when
    several transitions lead to a delete; None with a note when the delete does not hang on age."""
    states = policy.get("states") or []
    deleting = {st.get("name") for st in states if any("delete" in (a or {}) for a in st.get("actions") or [])}
    if not deleting:
        return None, "no delete action"
    ages, other = [], []
    for st in states:
        for t in st.get("transitions") or []:
            if t.get("state_name") in deleting:
                c = t.get("conditions") or {}
                d = _age_days(c.get("min_index_age"))
                (ages if d is not None else other).append(d if d is not None else json.dumps(c))
    if policy.get("default_state") in deleting:
        return 0, "the first state deletes"
    if ages:
        return max(ages), "min_index_age"
    return None, "the delete does not depend on the index's age (%s)" % ", ".join(other[:3])


def _covers(patterns):
    import fnmatch
    pats = patterns if isinstance(patterns, list) else [patterns]
    return any(fnmatch.fnmatchcase(sample, p) for p in pats if isinstance(p, str) for sample in ALERT_SAMPLES)


def retention_4x_of(policies, explain):
    """policies: GET /_plugins/_ism/policies; explain: GET /_plugins/_ism/explain/wazuh-alerts-4.x-* (index -> info).
    Returns what the bundle records: each policy that covers the alert indices (by its ism_template or because it is
    attached to one), its delete age, and the retention to carry (the longest delete age; None when none deletes)."""
    attached = {}
    for k, v in (explain or {}).items():
        if isinstance(v, dict):
            pid = v.get("index.plugins.index_state_management.policy_id") or v.get("policy_id") or v.get("index.opendistro.index_state_management.policy_id")
            if pid:
                attached.setdefault(pid, []).append(k)
    found = []
    for item in (policies or {}).get("policies") or []:
        pol = item.get("policy") or {}
        pid = item.get("_id") or pol.get("policy_id")
        tmpl = pol.get("ism_template") or []
        tmpl = tmpl if isinstance(tmpl, list) else [tmpl]
        pats = [p for t in tmpl for p in (t.get("index_patterns") or [])]
        by_t, by_a = _covers(pats), pid in attached
        if not (by_t or by_a):
            continue
        age, how = ism_delete_age(pol)
        found.append({"policy_id": pid, "index_patterns": pats, "covers_by": [x for x, y in (("ism_template", by_t), ("attached", by_a)) if y],
                      "attached_indices": len(attached.get(pid, [])), "delete_after_days": age, "how": how})
    ages = [f["delete_after_days"] for f in found if f["delete_after_days"] is not None]
    return {"policies": found, "retention_days": max(ages) if ages else None,
            "alert_indices": len([k for k in (explain or {}) if k.startswith("wazuh-alerts-")]),
            "alert_indices_with_policy": sum(len(v) for v in attached.values())}


_ISM_RO = ("policy_id", "last_updated_time", "schema_version", "seq_no", "primary_term")


def ism_record_of(policies, explain):
    """E3 fold: what going back needs to give 4.x its ISM policies back: every policy's body as PUT takes it
    (read-only fields dropped) and, per alert index, the policy attached to it. Going back reinstalls the 4.x indexer
    empty and reloads the alerts as new indices, so without this record the site lost its retention, and the next
    bundle read "no policy" and loaded 365 days."""
    pols = []
    for item in (policies or {}).get("policies") or []:
        pol = dict(item.get("policy") or {})
        pid = item.get("_id") or pol.get("policy_id")
        for k in _ISM_RO:
            pol.pop(k, None)
        if isinstance(pol.get("ism_template"), list):
            pol["ism_template"] = [{k: v for k, v in t.items() if k != "last_updated_time"} for t in pol["ism_template"] if isinstance(t, dict)]
        elif isinstance(pol.get("ism_template"), dict):
            pol["ism_template"] = {k: v for k, v in pol["ism_template"].items() if k != "last_updated_time"}
        else:
            pol.pop("ism_template", None)
        if pid:
            pols.append({"policy_id": pid, "policy": pol})
    attached = {}
    for k, v in (explain or {}).items():
        if isinstance(v, dict):
            pid = v.get("index.plugins.index_state_management.policy_id") or v.get("policy_id") or v.get("index.opendistro.index_state_management.policy_id")
            if pid:
                attached[k] = pid
    return {"policies": sorted(pols, key=lambda p: p["policy_id"]), "attached": dict(sorted(attached.items()))}


def durable_json(path, obj):
    """Written so a cut leaves the old file or the new one, never a partial one."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def ism_restore4(record, chunk=50):
    """E3 fold, going back: put the 4.x ISM policies back on the reinstalled 4.x indexer, then attach each
    restored alert index to the policy it had at the pre-copy. The policies go in after the alerts are reloaded, so an
    ism_template does not catch indices that had no policy before. A policy already there is kept, not replaced; an
    index now under another policy is named, not changed. Exit 1 when a policy or an attachment could not be made."""
    pw = os.environ["V4_INDEXER_ADMIN_PASSWORD"]
    try:
        rec = json.load(open(record))
    except (OSError, ValueError) as e:
        print("ism-restore4: no record of the 4.x ISM policies (%s): a bundle frozen before the E3 fold; if the 4.x site had "
              "ISM policies, create them again by hand (retention-4x.json names the ones on the alert indices)" % e)
        return 0
    bad = 0
    for p in rec.get("policies") or []:
        pid = p["policy_id"]
        c, _ = idx("GET", "/_plugins/_ism/policies/%s" % urllib.parse.quote(pid, safe=""), pw)
        if c == 200:
            print("ism-restore4: policy %s is already on the 4.x indexer: kept as it is" % pid)
            continue
        c, r = idx("PUT", "/_plugins/_ism/policies/%s" % urllib.parse.quote(pid, safe=""), pw, body={"policy": p["policy"]})
        if c in (200, 201):
            print("ism-restore4: policy %s put back" % pid)
        else:
            print("ism-restore4: policy %s could not be put back: HTTP %s %s" % (pid, c, json.dumps(r)[:300]))
            bad += 1
    by_pol = {}
    for i, pid in (rec.get("attached") or {}).items():
        by_pol.setdefault(pid, []).append(i)
    if not by_pol:
        print("ism-restore4: no alert index had a policy attached at the pre-copy")
        print("ism-restore4: %s" % ("the 4.x ISM policies are back" if not bad else "%d failure(s): see above" % bad))
        return 1 if bad else 0
    c, ex = idx("GET", "/_plugins/_ism/explain/wazuh-alerts-4.x-*", pw)
    if c != 200:
        print("ism-restore4: explaining the restored alert indices was refused: HTTP %s %s" % (c, json.dumps(ex)[:300]))
        return 1
    now = {k: (v.get("index.plugins.index_state_management.policy_id") or v.get("policy_id") or v.get("index.opendistro.index_state_management.policy_id"))
           for k, v in (ex or {}).items() if isinstance(v, dict)}
    for pid, idxs in sorted(by_pol.items()):
        todo, other, missing = [], [], []
        for i in idxs:
            if i not in now:
                missing.append(i)
            elif now.get(i) == pid:
                continue
            elif now.get(i):
                other.append("%s (%s)" % (i, now[i]))
            else:
                todo.append(i)
        if missing:
            print("ism-restore4: policy %s: %d index(es) it was attached to are not on the 4.x indexer: %s" % (pid, len(missing), " ".join(missing[:10])))
        if other:
            print("ism-restore4: policy %s: left as they are, now under another policy: %s" % (pid, " ".join(other[:10])))
        done = 0
        for n in range(0, len(todo), chunk):
            part = todo[n:n + chunk]
            c2, r = idx("POST", "/_plugins/_ism/add/%s" % ",".join(part), pw, body={"policy_id": pid})
            if c2 != 200 or (isinstance(r, dict) and r.get("failures")):
                print("ism-restore4: attaching %s to %d index(es) failed: HTTP %s %s" % (pid, len(part), c2, json.dumps(r)[:300]))
                bad += 1
            else:
                done += int((r or {}).get("updated_indices", len(part)))
        print("ism-restore4: policy %s attached to %d restored alert index(es) (%d already)" % (pid, done, len(idxs) - len(todo) - len(other) - len(missing)))
    restored_age_report(rec, pw, source_creation_dates(os.path.join(os.path.dirname(os.path.abspath(record)), "history")))
    print("ism-restore4: %s" % ("the 4.x ISM policies and their attachments are back" if not bad else "%d failure(s): see above" % bad))
    return 1 if bad else 0


def _day_end_ms(index):
    """End of the UTC day in a daily index's name (wazuh-alerts-4.x-YYYY.MM.DD), in epoch ms; None without a date."""
    m = re.search(r"(\d{4})\.(\d{2})\.(\d{2})$", index)
    if not m:
        return None
    import calendar
    try:
        return calendar.timegm((int(m.group(1)), int(m.group(2)), int(m.group(3)), 23, 59, 59)) * 1000 + 999
    except ValueError:
        return None


def _span(ms):
    """A length of time in the largest whole unit that fits (days, hours, minutes)."""
    for unit, size in (("day", 86400000), ("hour", 3600000), ("minute", 60000)):
        if ms >= size:
            return "%d %s(s)" % (ms // size, unit)
    return "less than a minute"


def source_creation_dates(history):
    """E5 fold: each source index's own creation date on 4.x, as the dump recorded it
    (<history>/indices/<index>.json "creation_date", ms); {} when the dump did not record one."""
    out = {}
    for f in glob.glob(os.path.join(history, "indices", "*.json")):
        try:
            cd = json.load(open(f)).get("creation_date")
        except (OSError, ValueError):
            continue
        if isinstance(cd, int):
            out[os.path.basename(f)[:-len(".json")]] = cd
    return out


def restored_age_report_of(rec, created, now_ms, source_created=None):
    """F4 item 2: what the ISM age of the restored alert indices means. ISM's min_index_age counts from the index's
    creation date; load_unchanged.py creates each restored index with the creation date the dump recorded (or the end of
    the day in its name). rec: ism-4x.json; created: index -> creation date (ms) on the reinstalled 4.x. Returns lines:
    indices already past their policy's delete age (ISM deletes them at its next run, as 4.x would have), and indices whose
    age counts from a date more than a day after their own (kept longer than on 4.x), with how much longer.
    E5 fold: where the dump recorded the index's own creation date on 4.x (source_created), the extra time
    is measured from it, not from the day in the index's name: a source whose indices were created after their day (a
    reload, a generator) was told "up to 146 day(s) longer" for 41 minutes. The day in the name stays the measure where
    4.x's date is not recorded."""
    ages = {p["policy_id"]: ism_delete_age(p.get("policy") or {})[0] for p in rec.get("policies") or []}
    source_created = source_created or {}
    due, late, by_source = [], [], 0
    for i, pid in sorted((rec.get("attached") or {}).items()):
        cd = created.get(i)
        if cd is None:
            continue
        sc, end = source_created.get(i), _day_end_ms(i)
        if sc is not None:
            if cd > sc + 60000:
                late.append((i, cd - sc))
                by_source += 1
        elif end is not None and cd > end + 86400000:
            late.append((i, cd - end))
        d = ages.get(pid)
        if d is not None and now_ms - cd >= d * 86400000:
            due.append(i)
    lines = []
    if due:
        lines.append("ism-restore4: %d restored alert index(es) are already past their policy's delete age; ISM deletes them at its "
                     "next run, as 4.x would have: %s" % (len(due), " ".join(due[:10]) + (" ..." if len(due) > 10 else "")))
    if late:
        measure = ("measured from each index's own creation date on 4.x" if by_source == len(late) else
                   "measured from each index's creation date on 4.x where the dump recorded it, else from the end of the day in its name"
                   if by_source else "measured from the end of the day in each index's name")
        lines.append("ism-restore4: WARNING %d restored alert index(es) count their ISM age from a date after their own %s (the "
                     "original creation date could not be carried): ISM keeps them up to %s longer than 4.x would have (%s); "
                     "delete them by hand when they are past the retention: %s" % (
                         len(late), "creation on 4.x" if by_source == len(late) else "day", _span(max(n for _, n in late)), measure,
                         " ".join(i for i, _ in late[:10]) + (" ..." if len(late) > 10 else "")))
    if not lines and created:
        lines.append("ism-restore4: every restored alert index counts its ISM age from its original creation date")
    return lines


def restored_age_report(rec, pw, source_created=None):
    c, st = idx("GET", "/wazuh-alerts-4.x-*/_settings/index.creation_date", pw)
    if c != 200 or not isinstance(st, dict):
        print("ism-restore4: the restored alert indices' creation dates could not be read (HTTP %s): their ISM age not checked" % c)
        return
    created = {}
    for i, v in st.items():
        try:
            created[i] = int(v["settings"]["index"]["creation_date"])
        except (KeyError, TypeError, ValueError):
            pass
    for line in restored_age_report_of(rec, created, int(time.time() * 1000), source_created):
        print(line)


def retention_4x(out):
    """Decision 5b: read the 4.x retention into the bundle (pre-copy). Rule 19: a refused read stops. the
    policies' bodies and the alert indices' attachments go to ism-4x.json beside it, for going back."""
    pw = os.environ["V4_INDEXER_ADMIN_PASSWORD"]
    c1, pols = idx("GET", "/_plugins/_ism/policies?size=1000", pw)
    if c1 == 404:
        pols = {"policies": []}            # no policy at all: the ISM index does not exist yet
    elif c1 != 200:
        print("retention-4x: reading the ISM policies was refused: HTTP %s %s (needs cluster:admin/opendistro/ism/policy/search)" % (c1, json.dumps(pols)[:300]))
        return 1
    c2, ex = idx("GET", "/_plugins/_ism/explain/wazuh-alerts-4.x-*", pw)
    if c2 != 200:
        print("retention-4x: explaining the alert indices was refused: HTTP %s %s (needs cluster:admin/opendistro/ism/managedindex/explain)" % (c2, json.dumps(ex)[:300]))
        return 1
    r = retention_4x_of(pols, ex)
    r["read_at"] = now_iso()
    rec = ism_record_of(pols, ex)
    rec["read_at"] = r["read_at"]
    durable_json(os.path.join(os.path.dirname(os.path.abspath(out)), "ism-4x.json"), rec)
    durable_json(out, r)
    for p in r["policies"]:
        print("4.x ISM policy %s covers the alert indices (%s): deletes after %s (%s)" % (
            p["policy_id"], "+".join(p["covers_by"]), "%d days" % p["delete_after_days"] if p["delete_after_days"] is not None else "no age", p["how"]))
    print("4.x retention of the alert indices: %s" % ("%d days" % r["retention_days"] if r["retention_days"] is not None else "none (no ISM policy deletes them)"))
    return 0


# ------------------------------------------------------------------------------- OF1 item 12: the source version
SOURCE_COMPONENTS = ("wazuh-manager", "wazuh-indexer", "wazuh-dashboard")


def _vtuple(v):
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", str(v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def source_policy(manifest=None):
    """(series, minimum) from the build manifest shipped with the tool (manifest/builds.json); no network lookup."""
    p = manifest or os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest", "builds.json")
    with open(p) as f:
        d = json.load(f)
    return d.get("source_series", "4.14"), d.get("source_min_version") or (d.get("source_4x") or ["4.14.11"])[-1]


def source_versions_check(rows, series, minimum):
    """decision of 2026-11-24: only the latest 4.14.x is a source. rows: (node, component, version); an empty version is a
    component not installed on that node (skipped). Returns (refusals, accepted lines)."""
    want, low = tuple(int(x) for x in series.split(".")), _vtuple(minimum)
    bad, good = [], []
    for node, comp, ver in rows:
        if not ver:
            continue
        t = _vtuple(ver)
        if t is None:
            bad.append("%s on %s: version %r cannot be read: not a 4.14 source the tool knows" % (comp, node, ver))
        elif t[:2] != want:
            bad.append("%s %s on %s is not a %s source: this tool migrates only %s.x (from %s) to 5.0" % (comp, ver, node, series, series, minimum))
        elif t < low:
            bad.append("%s %s on %s is older than %s, the newest %s.x this tool was released against: upgrade every node to the "
                       "latest %s.x first, then run the migration again" % (comp, ver, node, minimum, series, series))
        else:
            good.append("%s %s on %s%s" % (comp, ver, node, "" if t == low else " (WARNING: a %s.x newer than %s, the latest "
                                                                                  "this tool was validated on: accepted)" % (series, minimum)))
    return bad, good


_ASSISTANT_VERSION = re.compile(r'^[ \t]*(?:readonly[ \t]+)?wazuh_version=["\']?([0-9]+\.[0-9]+\.[0-9]+)["\']?[ \t]*(?:#.*)?$', re.M)


def assistant_version(path):
    """The version a 4.x installation assistant installs: its wazuh_version line ("4.14.11"), None when it has none."""
    try:
        m = _ASSISTANT_VERSION.search(open(path, errors="replace").read())
    except OSError:
        return None
    return m.group(1) if m else None


def v4_assistant_check(path, source="", how=""):
    """v4-assistant-check <assistant> <source version> [<how to give another file>]: the 4.x assistant removes 4.x and,
    when going back, reinstalls it, so it must install the source's own version. packages.wazuh.com/4.14/wazuh-install.sh
    serves only the latest 4.14.x: once a newer 4.14.x is published, the default URL would reinstall that newer version
    over a restore of the older one. Exit 1 on a mismatch or a file that names no version; 0 when they agree, or when the
    source's version is not known here (a bundle made before this check, its 4.x already removed)."""
    how = how or "V4_ASSISTANT=<path to that file>"
    a = assistant_version(path)
    if a is None:
        print("V4 ASSISTANT REFUSED: %s does not say which version it installs (no wazuh_version line): it is not a 4.x "
              "installation assistant this tool can check. Give the wazuh-install.sh of the source's own 4.14.x as %s" % (path, how))
        return 1
    s = _vtuple(source)
    if s is None:
        print("4.x assistant: %s installs %s; the source's version is not on record here, so it was not compared" % (path, a))
        return 0
    sv = "%d.%d.%d" % s
    if _vtuple(a) != s:
        print("V4 ASSISTANT REFUSED: the 4.x assistant %s installs %s, but this deployment runs %s. The tool removes 4.x "
              "with this file and, when going back, reinstalls 4.x with it, so it must install the source's own version "
              "(going back would otherwise put %s under a restore of %s). Give the %s installation assistant as %s: the "
              "wazuh-install.sh that installed this deployment, or a copy kept from then (https://packages.wazuh.com/4.14/"
              "wazuh-install.sh serves only the latest 4.14.x)%s. Nothing was changed by this step."
              % (path, a, sv, a, sv, sv, how, ", or upgrade the source to %s first" % a if _vtuple(a) > s else ""))
        return 1
    print("4.x assistant: %s installs %s, the source's own version" % (path, a))
    return 0


def source_version(node, *pairs):
    """source-version <node> <component> <version> [...]: the check for one node's installed packages."""
    series, minimum = source_policy()
    rows = [(node, pairs[i], pairs[i + 1] if i + 1 < len(pairs) else "") for i in range(0, len(pairs), 2)]
    bad, good = source_versions_check(rows, series, minimum)
    for g in good:
        print("source version: %s" % g)
    for b_ in bad:
        print("SOURCE VERSION REFUSED: %s" % b_)
    return 1 if bad else 0


def cluster_nodes_missing(connected, expected, registry):
    """E3 fold: /cluster/nodes lists only the nodes connected to the master, and a 4.x worker of
    another version cannot connect (Error 3031), so a mixed-version cluster passed the master's check. Every node the
    inventory names (expected) or the agent registry names as an agent's node (registry: {node: agents}) must be
    connected. Returns the refusals."""
    out = []
    for n in sorted(set(expected) | set(registry)):
        if n in connected:
            continue
        where = []
        if n in expected:
            where.append("the inventory (CLUSTER_NODES)")
        if n in registry:
            where.append("the agent registry (%d agent(s) last served by it)" % registry[n])
        out.append("manager node %s is not connected to the master, so its version cannot be read: named in %s. A 4.x worker "
                   "of another version cannot join (cluster error 3031): upgrade it to the latest 4.14.x, check that it joins "
                   "(cluster_control -l on the master), then run again (a node that no longer exists: remove it from the "
                   "inventory and move or remove its agents)" % (n, " and ".join(where)))
    return out


def source_version_cluster(*expect):
    """source-version-cluster [NODE,...]: every manager node of the 4.x cluster, from the 4.x Server API (/cluster/nodes) on
    the master (V4_API_PASSWORD), so a node that is not the one running the step is checked too; a node
    named by the inventory (arguments or CLUSTER_NODES) or by the agent registry that is not connected is refused by
    name. Rule 19: unreadable stops."""
    series, minimum = source_policy()
    api = Api(os.environ["V4_API_PASSWORD"])
    nodes = api.get("/cluster/nodes?limit=500")
    if isinstance(nodes, dict):
        print("source-version-cluster: the 4.x API refused /cluster/nodes: %s" % nodes)
        return 1
    agents = api.get("/agents?select=node_name&limit=100000")
    if isinstance(agents, dict):
        print("source-version-cluster: the 4.x API refused the agent list (each agent's node): %s" % agents)
        return 1
    registry = {}
    for a in agents:
        n = (a or {}).get("node_name") if isinstance(a, dict) else None
        if n and n != "unknown" and a.get("id") != "000":
            registry[n] = registry.get(n, 0) + 1
    expected = [x for e in list(expect) + [os.environ.get("CLUSTER_NODES", "")] for x in re.split(r"[,\s]+", e) if x]
    connected = {n.get("name") for n in nodes}
    missing = cluster_nodes_missing(connected, expected, registry)
    if not expected:
        print("source-version-cluster: no inventory given (CLUSTER_NODES): only the connected nodes and the nodes the agent "
              "registry names are checked")
    bad, good = source_versions_check([(n.get("name"), "wazuh-manager", n.get("version")) for n in nodes], series, minimum)
    bad += missing
    for g in good:
        print("source version: %s" % g)
    for b_ in bad:
        print("SOURCE VERSION REFUSED: %s" % b_)
    return 1 if bad or not nodes else 0


NEVER_CONNECTED = "never_connected"


def group_versions_of(agents):
    """{group: {agent id: version}} from API agent records (the post-upgrade group pass); agent 000 left out."""
    out = {}
    for a in agents:
        if not isinstance(a, dict) or a.get("id") == "000":
            continue
        v = a.get("version")
        if not v and a.get("status") == "never_connected":
            v = NEVER_CONNECTED        # named, so the post-upgrade pass can tell it from an unknown version
        for g in a.get("group") or []:
            out.setdefault(g, {})[a["id"]] = v
    return out


def group_versions():
    agents = Api(api_password5()).get("/agents?select=id,version,group,status&limit=100000")
    if isinstance(agents, dict):
        print("group-versions: the API refused the agent list: %s" % agents, file=sys.stderr)   # rule 19
        return 1
    print(json.dumps(group_versions_of(agents)))
    return 0


RAW_CHOICES = ("activate-force", "keep-raw", "accept-loss", "activated")
RAW_FACTS = "raw-at-finish-facts.json"
_RULE_ROW = re.compile(r"^\|?\s*\d+\s*\|")          # a per-rule row of verification.md: its first cell is a 4.x rule id
_NOT_ACTIVE = re.compile(r"NOT_REPRODUCED|NOT_SILENCED|NO_SAMPLE")


def raw_facts(state, rwork="", ruleset_src=""):
    """E5 fold: what the raw-at-finish refusal names, the rules not active (from
    rmig's verification.md) and the custom decoders (from the bundle's ruleset-src), recorded in <state>/raw-at-finish-
    facts.json while their sources exist, and read from there once they are gone. The first finish's secret sweep deletes
    ruleset-src, so a later refusal said "(no custom decoder found)" for the acmeshop decoders. Each part is taken from its
    source when the source is there, else from the record. only the per-rule rows
    of verification.md are rules; the summary table's count rows ("`NOT_REPRODUCED` | 1") were listed as rules too."""
    path = os.path.join(state, RAW_FACTS)
    try:
        rec = json.load(open(path))
    except (OSError, ValueError):
        rec = {}
    out = dict(rec)
    vf = os.path.join(rwork, "verification.md") if rwork else ""
    if vf and os.path.isfile(vf):
        rules = []
        for line in open(vf, errors="replace"):
            if _RULE_ROW.match(line.strip()) and _NOT_ACTIVE.search(line):
                rules.append(re.sub(r"\s+", " ", line.strip(" |-*\n"))[:160])
        out["rules_not_active"], out["rules_from"] = rules, vf
    # R1 (items 3, 5): rules rmig left out because stock 5.0 covers them, and telemetry rules (--findings mitre), are no
    # "rule not active": recorded with the rest, from rmig's report
    if rwork and os.path.isfile(os.path.join(rwork, "report.json")):
        k = ruleset_kinds(rwork)
        out["covered_rules"], out["telemetry_rules"] = k["covered"], sorted(k["telemetry"] + k["untagged"])
    skip = set(out.get("covered_rules") or {}) | set(out.get("telemetry_rules") or [])
    if skip and out.get("rules_not_active"):
        out["rules_not_active"] = [r for r in out["rules_not_active"] if r.split(" ", 1)[0] not in skip]
    dd = os.path.join(ruleset_src, "etc", "decoders") if ruleset_src else ""
    if dd and os.path.isdir(dd):
        decoders = []
        for f in sorted(glob.glob(os.path.join(dd, "*.xml"))):
            decoders += re.findall(r'<decoder\s+name="([^"]+)"', open(f, errors="replace").read())
        out["custom_decoders"], out["decoders_from"] = sorted(set(decoders)), dd
    if out != rec and os.path.isdir(state):
        out["recorded_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        durable_json(path, out)
    return out.get("rules_not_active") or [], out.get("custom_decoders") or [], "custom_decoders" in rec and not (dd and os.path.isdir(dd))


def raw_facts_cmd(state, rwork="", ruleset_src=""):
    """CLI: record the raw-at-finish facts while their sources exist (the finish calls it before anything can delete them)."""
    rules, decoders, _ = raw_facts(state, rwork, ruleset_src)
    print("raw at the finish: %d rule(s) without a clean verification and %d custom decoder(s) on record (%s)" % (len(rules), len(decoders), os.path.join(state, RAW_FACTS)))
    return 0


def rmig_active(rwork):
    """E5 fold: the answer "activated" is checked against rmig's own record on this node
    (<rwork>/work/state.json, written by rmig apply and activate): an activation recorded, every rule of the tool's content
    (outside an integration set aside) in the custom space, and at least one detector. Returns (True, what) or (False,
    why). Before, the answer was taken on the person's word, and a wrong one dropped every custom-log event."""
    p = os.path.join(rwork, "work", "state.json")
    try:
        st = json.load(open(p))
    except (OSError, ValueError) as e:
        return False, "rmig's record %s cannot be read (%s): no activation is recorded on this node" % (p, e.__class__.__name__)
    aside = set(st.get("set_aside") or {})
    res = [(lid, e) for lid, e in (st.get("resources") or {}).items() if isinstance(e, dict) and e.get("integration") not in aside]
    rules = [(lid, e) for lid, e in res if e.get("type") == "rule"]
    not_custom = sorted((e.get("title") or lid) for lid, e in rules if e.get("space") != "custom")
    dets = st.get("detectors") or {}
    if not st.get("last_activate"):
        return False, "rmig's record shows no activation (last_activate is empty; %d rule(s) in the test space)" % len(not_custom)
    # with --findings mitre a rule without MITRE is telemetry: its 4.x rule.id, rule.description and
    # rule.level are written by its decoder, so it is in force once the decoders are in the custom space; it is no
    # detection rule and has no detector. A build of telemetry only is active without any rule or detector.
    tele = ruleset_kinds(rwork)["telemetry"]
    if tele:
        decs = [(lid, e) for lid, e in res if e.get("type") == "decoder"]
        dn = sorted((e.get("title") or lid) for lid, e in decs if e.get("space") != "custom")
        if not decs or dn:
            return False, "%d telemetry rule(s) are tagged by decoders that are not in the custom space%s" % (
                len(tele), (": " + ", ".join(dn[:10])) if dn else " (no decoder recorded)")
        if not rules:
            return True, "activated %s: %d telemetry rule(s) tagged by %d decoder(s) in the custom space, no detection rule (no detector needed)" % (
                st["last_activate"], len(tele), len(decs))
    if not rules:
        return False, "rmig's record holds no migrated rule"
    if not_custom:
        return False, "%d of %d migrated rule(s) are not in the custom space: %s" % (len(not_custom), len(rules), ", ".join(not_custom[:10]))
    if not dets:
        return False, "no detector is recorded: the activated rules run on no index"
    return True, "activated %s: %d rule(s) in the custom space, detector(s) %s" % (st["last_activate"], len(rules), ", ".join(sorted(dets)))


def verify_summary_md(rwork):
    """The counts of rmig's latest verification.md ("verify: REPRODUCED 5, NOT_REPRODUCED 1, ..., run <time>"), or "".
    The tool's own summary is the import's; a verify run since (by hand, after a rule was answered) changed the counts
    and the finish kept printing the first ones."""
    try:
        text = open(os.path.join(rwork, "verification.md"), errors="replace").read() if rwork else ""
    except OSError:
        return ""
    rows = re.findall(r"^\|\s*`([A-Z_]+)`\s*\|\s*(\d+)\s*\|\s*$", text, re.M)
    if not rows:
        return ""
    run = re.search(r"^Run (\S+)", text, re.M)
    return "verify: %s (rmig's verification.md%s)" % (", ".join("%s %s" % r for r in rows), ", run %s" % run.group(1) if run else "")


VERIFY_WORDS = {"NOT_REPRODUCED": "did not match its 4.x alerts on 5.0", "NOT_SILENCED": "did not silence the alerts it silences on 4.x",
                "NO_SAMPLE": "had no 4.x alert to check it against"}


def unverified_rules(rwork):
    """["rule 100300: did not match its 4.x alerts on 5.0 (<the ruleset tool's reason>)", ...]: every migrated rule the
    verification did not pass, with the reason the ruleset tool gives (verification.json), in the person's words."""
    try:
        doc = json.load(open(os.path.join(rwork, "verification.json")))
    except (OSError, ValueError):
        return []
    out = []
    for e in doc.get("rules") or []:
        res = e.get("result")
        if res not in VERIFY_WORDS:
            continue
        why = "; ".join(re.sub(r"\s*\(?RM-[A-Z]-[A-Z0-9-]+\)?:?\s*", " ", w).strip() for w in (e.get("not_met") or [])[:3])
        out.append("rule %s: %s%s" % (e.get("rule_id_4x"), VERIFY_WORDS[res], (" (%s)" % why[:300]) if why else ""))
    return out


def raw_decision(decisions, state, rwork="", ruleset_src=""):
    """design decision 3 follow-up: raw event indexing is switched off at the finish only
    when every migrated rule is active, or on an explicit answer. Before, the finish switched it off "once no 4.x agent
    remains" while rmig had activated nothing (one rule NOT_REPRODUCED), and every custom-log event was dropped from
    then on. Exit 0: raw may go off (the rules were activated, or the user answered "activated" and rmig's record agrees,
    or "accept-loss"); 4: the user answered "keep-raw"; 5: "activate-force" (the caller activates, then raw goes off); 3: refused, the question written into the decisions file (section
    "unclassified-finish"), naming the rules not active and the custom decoders whose events would be dropped. Every
    answer taken is recorded in <state>/raw.decision."""
    applied = open(os.path.join(state, "unclassified.applied")).read().split() if os.path.exists(os.path.join(state, "unclassified.applied")) else []
    if any(x in ("activate", "activate-force") for x in applied):
        print("raw at the finish: the migrated rules are active (%s): raw indexing can go off" % " ".join(applied))
        return 0
    rules, decoders, from_record = raw_facts(state, rwork, ruleset_src)
    summary = verify_summary_md(rwork) or (open(os.path.join(state, "ruleset.verify_summary")).read().strip() if os.path.exists(os.path.join(state, "ruleset.verify_summary")) else "no verification summary")
    d = load(os.path.dirname(decisions) or ".", os.path.basename(decisions)) or {}
    sec = d.get("unclassified-finish") or []
    ent = next((e for e in sec if e.get("id") == "raw-at-finish"), None) or {}
    ans = ent.get("action")
    refused = None
    if ans == "activated":
        ok, what = rmig_active(rwork)
        if ok:
            print("raw at the finish: the answer \"activated\" agrees with rmig's record (%s)" % what)
        else:
            refused = what
    if ans in RAW_CHOICES and refused is None:
        with open(os.path.join(state, "raw.decision"), "w") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), ans))
        print("raw at the finish: answered \"%s\" in %s (recorded in state/raw.decision)" % (ans, decisions))
        return 4 if ans == "keep-raw" else (5 if ans == "activate-force" else 0)
    q = {"id": "raw-at-finish", "action": None, "choices": list(RAW_CHOICES),
         "question": "The migrated rules are not active (%s; decision applied: %s), so the events only your custom decoders "
                     "classify reach 5.0 through raw event indexing alone. Switching raw off at the finish drops them. Answer: "
                     "\"activate-force\" to have the tool activate the migrated rules anyway at the finish (their verification is "
                     "kept in %s/verification.md), \"keep-raw\" to keep raw indexing on, \"accept-loss\" to switch it off and lose those "
                     "events, or \"activated\" once you have activated them yourself (the tool checks the ruleset tool's record)."
                     % (summary, " ".join(applied) or "none", rwork or "<the ruleset work directory>")
                     + ("".join(" Not verified: %s." % u for u in unverified_rules(rwork)[:10]) if rwork else ""),
         "rules_not_active": rules[:50], "custom_decoders": decoders[:100]}
    if refused is not None:
        q["refused"] = {"answer": {"action": "activated"}, "why": refused, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    d["unclassified-finish"] = [e for e in sec if e.get("id") != "raw-at-finish"] + [q]
    write(os.path.dirname(decisions) or ".", os.path.basename(decisions), d)
    if refused is not None:
        print("RAW INDEXING NOT SWITCHED OFF: you answered \"activated\", but %s. Answer \"activate-force\" to have the tool "
              "activate them at the finish (the ruleset review must be accepted first), or keep-raw or accept-loss, and run %s "
              "again." % (refused, run_again()))
    else:
        print("RAW INDEXING NOT SWITCHED OFF: the migrated rules are not active (%s)." % summary)
    for r in rules[:20]:
        print("  rule not active: " + r)
    for u in (unverified_rules(rwork) if rwork else [])[:20]:
        print("  why: " + u)
    print("  events of these custom decoders would be dropped with raw off: %s%s" % (", ".join(decoders[:30]) or "(no custom decoder found)",
                                                                                   " (as recorded before the bundle's ruleset copy was deleted)" if from_record and decoders else ""))
    cov, tele = raw_kinds(state)
    if cov:
        print("  not counted: %d rule(s) left out because stock 5.0 covers them: %s" % (len(cov), ", ".join(sorted(cov)[:20])))
    if tele:
        print("  not counted as detection rules: %d telemetry rule(s), in force through their decoder once activated: %s" % (len(tele), ", ".join(tele[:20])))
    print("  answer the entry \"raw-at-finish\" (section \"unclassified-finish\") in %s: activate-force, keep-raw, accept-loss or activated, and run %s again" % (os.environ.get("DECISIONS_SHOWN") or decisions, run_again()))
    return 3


def raw_kinds(state):
    try:
        rec = json.load(open(os.path.join(state, RAW_FACTS)))
    except (OSError, ValueError):
        rec = {}
    return rec.get("covered_rules") or {}, rec.get("telemetry_rules") or []


# ------------------------------------------------------------------ the ruleset tool (rmig) at the commit the build manifest pins
RMIG_REVIEW_BLOCK = "## Review before activate"
COVERED_CODE, TELEMETRY_CODES = "RM-S-STOCK-COVERED", ("RM-R-TELEMETRY", "RM-R-TELEMETRY-UNTAGGED")


def rmig_pin():
    """The rmig commit this tool was tested with (manifest/builds.json, ruleset_tool)."""
    return build_manifest().get("ruleset_tool") or {}


def rmig_check(rmig_dir):
    """R1: the ruleset tool at rmig_dir knows what this tool passes it and reads from it: the mandatory review
    (RM-P-REVIEW-PENDING), --findings on migrate, plan and build, and --engine-limit on activate. An older rmig refuses
    --findings (exit 2) and never stops for the review. The commit is named when the directory is a git checkout."""
    pin = rmig_pin()
    want = (pin.get("commit") or "")[:12] or "the pinned commit"
    need = {"rmig/reasons.py": "RM-P-REVIEW-PENDING", "rmig/cli.py": "--findings", "rmig/api/commands.py": "--engine-limit"}
    missing = []
    for rel, token in need.items():
        try:
            txt = open(os.path.join(rmig_dir, rel), errors="replace").read()
        except OSError:
            txt = ""
        if token not in txt:
            missing.append("%s (%s)" % (token, rel))
    head = ""
    try:
        head = subprocess.run(["git", "-C", rmig_dir, "rev-parse", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              universal_newlines=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    at = (" at commit %s" % head[:12]) if re.fullmatch(r"[0-9a-f]{40}", head or "") else ""
    if missing:
        print("ruleset tool %s%s is older than the one this tool was tested with (%s, %s): it lacks %s"
              % (rmig_dir, at, want, pin.get("source", "tools/ruleset-migration"), ", ".join(missing)))
        return 1
    note = "" if not at or head.startswith(pin.get("commit", "-")) else " (tested with %s)" % want
    print("ruleset tool %s%s: mandatory review, --findings and the detector cap known%s" % (rmig_dir, at, note))
    return 0


def _report_items(rwork):
    try:
        return json.load(open(os.path.join(rwork, "report.json"))).get("items") or []
    except (OSError, ValueError, AttributeError):
        return []


def ruleset_kinds(rwork):
    """Rule ids rmig left out because stock 5.0 covers them, and the rules it made telemetry (--findings mitre):
    {"covered": {id: stock rule}, "telemetry": [id], "untagged": [id]} from report.json and decisions.json."""
    try:
        cov = json.load(open(os.path.join(rwork, "decisions.json"))).get("covered") or {}
    except (OSError, ValueError, AttributeError):
        cov = {}
    out = {"covered": {}, "telemetry": [], "untagged": []}
    for it in _report_items(rwork):
        if it.get("kind") != "rule":
            continue
        rid = str(it.get("ref", "")).split(":", 1)[-1]
        codes = {c.get("code") for c in it.get("codes") or []}
        if COVERED_CODE in codes:
            out["covered"][rid] = (cov.get(rid) or {}).get("stock_rule") or "a stock 5.0 rule"
        elif "RM-R-TELEMETRY" in codes:
            out["telemetry"].append(rid)
        elif "RM-R-TELEMETRY-UNTAGGED" in codes:
            out["untagged"].append(rid)
    return out


def review_state(decisions_file):
    try:
        return (json.load(open(decisions_file)) or {}).get("review")
    except (OSError, ValueError, AttributeError):
        return None


def run_again():
    """How the person runs the tool again: the one-file tool's own name (WM_SELF), passed to every node step too."""
    return os.environ.get("WM_SELF") or "./wazuh-migrate.sh"


def review_customer(text, rwork):
    """rmig's review block speaks of rmig's own commands, files and codes ("then run plan again", "`activate` stops
    (`RM-P-REVIEW-PENDING`)", "decisions.json", "out/recipes/"): the person runs only this tool and answers in its
    decisions file. The same block, with each such instruction said the way this tool takes it."""
    shown = os.environ.get("DECISIONS_SHOWN") or "the decisions file"
    subs = (
        (r"The review is mandatory: `activate` stops \(`RM-P-REVIEW-PENDING`\) until decisions\.json has `\"review\": \"accepted\"`( \(accepted\))?",
         lambda m: "The review is mandatory: the migrated rules are not activated until \"review\" is \"accepted\" in %s, section \"ruleset\"%s"
         % (shown, " (accepted)" if m.group(1) else "")),
        (r"compare each pair in decisions\.json \(`covered`\), and set `action` to `migrate`",
         lambda m: "compare each pair in %s (section \"ruleset\", part \"covered\"), and set \"action\" to \"migrate\"" % shown),
        (r"Apply, verify, then activate\.", lambda m: "The tool loads them, checks them against your 4.x alerts and activates them."),
        (r"Answer the entries of decisions\.json, then run plan again\.",
         lambda m: "Answer the questions listed under QUESTION, then run %s again." % run_again()),
        (r"\(out/recipes/\)", lambda m: "(%s)" % os.path.join(rwork, "out", "recipes")),
        (r"`--findings mitre`: ", lambda m: ""),
        (r"`([^`]*)`", lambda m: m.group(1)),
    )
    for rx, f in subs:
        text = re.sub(rx, f, text)
    return text


def ruleset_review_show(rwork):
    """R1: the block "Review before activate" of rmig's report.md, as the user must read it, then the rules
    left out because stock 5.0 covers them (each with its stock rule and how to build it anyway), the telemetry
    rules and the path to the whole report."""
    rep = os.path.join(rwork, "report.md")
    try:
        lines = open(rep, errors="replace").read().splitlines()
    except OSError:
        print("ruleset review: no report.md in %s" % rwork)
        return 0
    block, on = [], False
    for l in lines:
        if l.startswith(RMIG_REVIEW_BLOCK):
            on = True
        elif on and l.startswith("## "):
            break
        if on:
            block.append(l)
    print("---- the ruleset tool's review (%s) ----" % rep)
    print(review_customer("\n".join(block).strip(), rwork) or "(the ruleset report has no \"Review before activate\" block: the ruleset tool is older than the one this tool needs)")
    k = ruleset_kinds(rwork)
    if k["covered"]:
        print("left out because stock 5.0 covers them (not built, not \"rules not active\" at the finish):")
        for rid, stock in sorted(k["covered"].items()):
            print("  rule %s: %s" % (rid, stock))
        print("  to build one anyway: \"action\": \"migrate\" in its entry of the \"covered\" part of the ruleset decisions")
    if k["telemetry"] or k["untagged"]:
        print("telemetry: %d rule(s) tagged in their decoder (rule.id, rule.description, rule.level of the 4.x rule), "
              "%d untagged: not detection rules%s" % (len(k["telemetry"]), len(k["untagged"]),
                                                      (": " + ", ".join(sorted(k["telemetry"] + k["untagged"])[:20]))))
    print("the whole report: %s" % rep)
    print("----")
    return 0


def ruleset_review_ask(flow, rwork, own_file=""):
    """R1: rmig's activate stops (RM-P-REVIEW-PENDING, --force does not skip it) until its decisions.json says
    "review": "accepted". The question goes into the flow's decisions file, section "ruleset" (rmig's decisions.json,
    which the next run carries into rmig), or stays in RMIG_DECISIONS when the user keeps a file of their own. Exit 0:
    accepted; 3: open, the run stops before the freeze. The tool never writes "accepted": only the user does."""
    if review_state(os.path.join(rwork, "decisions.json")) == "accepted":
        print("ruleset review: accepted (\"review\": \"accepted\" in %s)" % (own_file or "%s, section \"ruleset\"" % (os.environ.get("DECISIONS_SHOWN") or flow)))
        return 0
    if own_file:
        where = "%s (your own ruleset decisions file)" % own_file
    else:
        d = load(os.path.dirname(flow) or ".", os.path.basename(flow)) or {}
        sec = d.get("ruleset")
        if not isinstance(sec, dict) or not sec:
            try:
                sec = json.load(open(os.path.join(rwork, "decisions.json")))
            except (OSError, ValueError):
                sec = {"version": 1}
        if sec.get("review") != "accepted":
            sec["review"] = None
        d["ruleset"] = sec
        write(os.path.dirname(flow) or ".", os.path.basename(flow), d)
        where = "%s, section \"ruleset\"" % (os.environ.get("DECISIONS_SHOWN") or flow)
    print("RULESET REVIEW OPEN: the migrated rules are not activated until you accept the review. Read the block "
          "\"Review before activate\" above (the whole report: %s), then set \"review\" to \"accepted\" in %s and run %s "
          "again. The run stops here, before the freeze; nothing is answered for you."
          % (os.path.join(rwork, "report.md"), where, run_again()))
    return 3


def ruleset_review(action, *args):
    return {"show": ruleset_review_show, "ask": ruleset_review_ask}[action](*args)


def ruleset_answers_differ(answered, fresh):
    """R1: the flow's ruleset section holds an answer rmig's fresh decisions.json lacks (a null review is no answer)."""
    def norm(p):
        d = json.load(open(p))
        if d.get("review") is None:
            d.pop("review", None)
        return d
    try:
        return 0 if norm(answered) != norm(fresh) else 1
    except (OSError, ValueError, AttributeError):
        return 1


def ruleset_open(rwork):
    """ruleset-open <rmig workdir>: the items rmig's last plan left waiting for an answer (state DECISION), one line each
    with the entries that would close them. Exit 1 when there is one."""
    try:
        items = json.load(open(os.path.join(rwork, "report.json"))).get("items") or []
    except (OSError, ValueError, AttributeError):
        return 0
    n = 0
    for it in items:
        if it.get("state") != "DECISION":
            continue
        n += 1
        why = ["%s %s" % (c.get("code"), ", ".join(c.get("details") or [])) for c in it.get("codes") or [] if c.get("state") == "DECISION"]
        print("  %s (%s): %s" % (it.get("ref") or it.get("uid"), it.get("origin") or it.get("file") or "?", "; ".join(w.strip() for w in why) or "a decision"))
    return 1 if n else 0


def _merge_new(old, new):
    """Entries of `new` that `old` lacks are added (recursively); every value already in `old` is kept as written."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return old
    out = dict(old)
    for k, v in new.items():
        out[k] = _merge_new(old[k], v) if k in old else v
    return out


def ruleset_merge(where, target, rmig_decisions):
    """ruleset-merge flow|own <file> <rmig decisions.json>: rmig's plan opened new questions from the first answers (a
    field once a covered rule is answered "migrate", a findings entry once a stock reference is answered). They go where
    the user answers: the flow file's "ruleset" section, or the user's own RMIG_DECISIONS file; every answer already
    there is kept as written."""
    new = json.load(open(rmig_decisions))
    d = load(os.path.dirname(target) or ".", os.path.basename(target)) or {}
    if where == "flow":
        d["ruleset"] = _merge_new(d.get("ruleset") or {}, new)
    else:
        d = _merge_new(d, new)
    write(os.path.dirname(target) or ".", os.path.basename(target), d)
    return 0


def ruleset_carry(way, cdec, nodefile, out=""):
    """ruleset-carry to-node|from-node <controller decisions> <node decisions> [<out>]: on a cluster the ruleset tool runs
    on the master and its questions (the review included) were answered in the master's own file, while every other
    question is in the controller's decisions file. The person answers the "ruleset" section in the controller's file;
    to-node writes the node's file with that section in it (to <out>), from-node moves the section the node step left
    in the node's file into the controller's, keeping every answer already there and adding the new entries."""
    c = load(os.path.dirname(cdec) or ".", os.path.basename(cdec)) or {}
    n = load(os.path.dirname(nodefile) or ".", os.path.basename(nodefile)) or {}
    if way == "to-node":
        if isinstance(c.get("ruleset"), dict) and c["ruleset"]:
            n["ruleset"] = _merge_new(c["ruleset"], n.get("ruleset") or {})
        write(os.path.dirname(out) or ".", os.path.basename(out), n)
        return 0
    rs = n.pop("ruleset", None)
    hints = n.pop("ruleset-hints", None)
    if isinstance(hints, dict):
        c["ruleset-hints"] = hints          # the candidates the master found for its stock questions (always the newest)
    if not isinstance(rs, dict) or not rs:
        if isinstance(hints, dict):
            write(os.path.dirname(cdec) or ".", os.path.basename(cdec), c)
            write(os.path.dirname(nodefile) or ".", os.path.basename(nodefile), n)
        return 0
    c["ruleset"] = _merge_new(c.get("ruleset") or {}, rs)
    write(os.path.dirname(cdec) or ".", os.path.basename(cdec), c)
    write(os.path.dirname(nodefile) or ".", os.path.basename(nodefile), n)
    return 0


def _stock4_rules(src):
    """{rule id: {"decoded_as", "if_sid": [...], "groups": [...]}} of the 4.x rule files under <src>/ruleset/rules (and
    <src>/etc/rules): a line reader, since 4.x rule files are not one XML document."""
    rules, top, cur = {}, [], None
    for d in (os.path.join(src, "ruleset", "rules"), os.path.join(src, "etc", "rules")):
        for f in sorted(glob.glob(os.path.join(d, "*.xml"))):
            try:
                text = open(f, errors="replace").read()
            except OSError:
                continue
            text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
            for line in text.splitlines():
                m = re.search(r'<group\s+name="([^"]*)"', line)
                if m and cur is None:
                    top = [g.strip() for g in m.group(1).split(",") if g.strip()]
                m = re.search(r'<rule\s+id="(\d+)"', line)
                if m:
                    cur = rules.setdefault(m.group(1), {"decoded_as": None, "if_sid": [], "groups": list(top)})
                if cur is not None:
                    for tag, val in re.findall(r"<(decoded_as|if_sid|if_matched_sid|group|if_group)>([^<]*)</\1>", line):
                        vals = [v.strip() for v in re.split(r"[,\s]+", val) if v.strip()]
                        if tag == "decoded_as":
                            cur["decoded_as"] = val.strip()
                        elif tag in ("if_sid", "if_matched_sid"):
                            cur["if_sid"] += vals
                        else:
                            cur["groups"] += vals
                    if "</rule>" in line:
                        cur = None
    return rules


def _words(s):
    return [w for w in re.split(r"[^a-z0-9]+", (s or "").lower()) if len(w) >= 3]


def stock_candidates(key, rules, integrations):
    """The 5.0 integrations whose names (or decoders' names) share a word with the 4.x stock rule's decoder and groups,
    walking its parents: candidates to check, never an answer."""
    kind, _, name = key.partition(":")
    seen, todo, dec, groups = set(), [name] if kind == "rule" else [], [], []
    if kind == "group":
        groups.append(name)
    if kind == "decoder":
        dec.append(name)
    while todo and len(seen) < 20:
        r = todo.pop(0)
        if r in seen or r not in rules:
            continue
        seen.add(r)
        if rules[r]["decoded_as"]:
            dec.append(rules[r]["decoded_as"])
        groups += rules[r]["groups"]
        todo += rules[r]["if_sid"]
    groups = [g for g in groups if not re.match(r"(gdpr|pci|nist|hipaa|tsc|gpg13)_", g, re.I)]   # compliance tags say nothing of the source
    stop = {"syslog", "rule", "rules", "alert", "alerts", "event", "events", "failed", "failure", "success", "decoder", "wazuh", "normalized"}
    dw = set(w for x in dec for w in _words(x)) - stop
    gw = set(w for x in groups for w in _words(x)) - stop - dw

    def hits(mine, words):
        return sum(1 for t in mine if any(t == w or (min(len(t), len(w)) >= 4 and (t.startswith(w) or w.startswith(t))) for w in words))
    scored = []
    for iname, info in integrations.items():
        nw = set(_words(iname)) - stop
        dn = set(w for d2 in (info.get("decoders") or []) for w in _words(d2.split("/")[1] if "/" in d2 else d2)) - stop
        s = 4 * hits(dw, nw) + 2 * hits(dw, dn) + 2 * hits(gw, nw) + hits(gw, dn)   # the decoder weighs more than a group
        if s:
            scored.append((-s, iname))
    scored.sort()
    top = -scored[0][0] if scored else 0
    groups = [g for g in groups if g]
    return [n for s, n in scored if -s * 2 >= top][:4], sorted(set(dec)), sorted(set(groups))


def ruleset_hints(flow, src, rmig_dir):
    """ruleset-hints <flow decisions> <ruleset source dir> <rmig dir>: for every open "stock" question of the ruleset
    section, the 5.0 integrations that may match (by name) and where the 5.0 field names are, into the flow file's own
    "ruleset-hints" section (never into the ruleset section: rmig reads that one). The question then names them."""
    d = load(os.path.dirname(flow) or ".", os.path.basename(flow)) or {}
    stock = ((d.get("ruleset") or {}).get("stock") or {}) if isinstance(d.get("ruleset"), dict) else {}
    try:
        integ = json.load(open(os.path.join(rmig_dir, "rmig", "data", "stock5-index.json"))).get("integrations") or {}
    except (OSError, ValueError, AttributeError):
        integ = {}
    rules = _stock4_rules(src) if stock else {}
    fields = os.path.join(rmig_dir, "rmig", "data", "wcs-fields.csv")
    hints = {}
    for key in sorted(stock):
        cands, dec, groups = stock_candidates(key, rules, integ)
        hints["stock/" + key] = {"candidates": cands, "decoders_4x": dec, "groups_4x": groups[:12],
                                 "fields_file": fields if os.path.isfile(fields) else None}
    if hints or "ruleset-hints" in d:
        d["ruleset-hints"] = hints
        write(os.path.dirname(flow) or ".", os.path.basename(flow), d)
    return 0


def node_carry(way, cdec, node, nodefile, out=""):
    """node-carry to-node|from-node <controller decisions> <node> <node decisions> [<out>]: on a cluster every question a
    node step asks (the settings of each manager, the finish's raw question on the master) is answered in the controller's
    one decisions file, under "nodes" -> "<node>". from-node takes the node's sections (all but the ruleset's, which
    ruleset-carry moves) into the controller's file; to-node writes the node's file (to <out>) with the controller's
    sections, which hold the person's answers. The node's file is the node step's own copy; the person never edits it."""
    c = load(os.path.dirname(cdec) or ".", os.path.basename(cdec)) or {}
    n = load(os.path.dirname(nodefile) or ".", os.path.basename(nodefile)) or {}
    if way == "to-node":
        for k, v in ((c.get("nodes") or {}).get(node) or {}).items():
            n[k] = v
        if n:
            write(os.path.dirname(out) or ".", os.path.basename(out), n)
        return 0
    mine = {k: v for k, v in n.items() if k not in ("ruleset", "ruleset-hints")}
    nodes = c.get("nodes") if isinstance(c.get("nodes"), dict) else {}
    if not mine and node not in nodes:
        return 0
    if mine:
        nodes[node] = mine
    else:
        nodes.pop(node, None)
    c["nodes"] = nodes
    write(os.path.dirname(cdec) or ".", os.path.basename(cdec), c)
    return 0


def rmig_outcome(cmd, log, rc=""):
    """R1 (items 4, 6): what an rmig exit 1 or 2 means, from its own last lines. rmig's exit codes: 0 done, 1 done with
    items waiting (apply: an integration set aside; activate: a detector left out), 2 stopped with nothing written. Two
    stops still exit 1 (activate after a verification with failures, apply when the engine refuses the root decoder's
    integration): "<cmd>: stopped" tells them apart. Prints rmig's stop line and items; RM-P-ENGINE-LIMIT and
    RM-P-REVIEW-PENDING get what the user does next. Exit 0: done (with items waiting); 3: stopped on something the user
    answers or raises; 1: stopped otherwise."""
    try:
        lines = open(log, errors="replace").read().splitlines()
    except OSError:
        lines = []
    stop = [i for i, l in enumerate(lines) if l.startswith("%s: stopped" % cmd)]
    if not stop:
        last = [l for l in lines if l.startswith("%s:" % cmd)]
        if str(rc) == "2":
            # exit 2 is rmig's "stopped, nothing written": never "done with items waiting" (E7-aio, the indexer stopped)
            tail = [l for l in lines if l.strip()][-3:]
            print("rmig %s stopped (exit %s), nothing changed: %s" % (cmd, rc or "?", " | ".join(tail) or "no output"))
            return 1
        print("rmig %s: done with items waiting: %s" % (cmd, last[-1] if last else "(no result line)"))
        return 0
    i = stop[0]
    print(lines[i])
    for l in lines[i + 1:]:
        if not l.startswith("  - "):
            break
        print(l)
    text = lines[i]
    if "RM-P-ENGINE-LIMIT" in text:
        print("DETECTOR CAP: rmig changed nothing. Raise the setting it names on the 5.0 indexer (PUT _cluster/settings, "
              "for example {\"persistent\": {\"plugins.security_analytics.max_detectors\": N}}) or remove detectors you do "
              "not use, then run again with RMIG_ENGINE_LIMITS=\"max_detectors=N\" (the tool passes it to rmig as "
              "--engine-limit max_detectors=N)")
        return 3
    if "RM-P-REVIEW-PENDING" in text:
        print("the ruleset review is not accepted: set \"review\": \"accepted\" in the \"ruleset\" section of the decisions "
              "file (or in RMIG_DECISIONS) after reading \"Review before activate\" in report.md, and run again")
        return 3
    return 1


# ------------------------------------------------------------------ R1 extra item 10: the 5.0 indexer heap
# "4 GB" as the 5.0 assistant gives it on a 16 GB host: free -m reads less than the nominal size (the assistant itself
# allows 700 MB per 8 GB), so a quarter of a 16 GB host is 3,800 to 3,950 MB; E4-breaker's 3,946 MB heap passed
HEAP_MIN_MB = 3800
HEAP_WHY = ("E4-breaker (2026-11-25): at 1.85 GB the 5.0 indexer tripped its parent breaker 38 times in 15 minutes with "
            "no history load at all, and the full 5 M-alert load took 2 h 7 min with 524 trips and 142 HTTP 429s to the "
            "manager's modules even with the loader's guard; at 3.9 GB, 0 to 2 trips")


def heap_lines(stats):
    """[(node name, heap MB)] from GET _nodes/stats/jvm."""
    out = []
    for nid, n in sorted(((stats or {}).get("nodes") or {}).items()):
        b = (((n or {}).get("jvm") or {}).get("mem") or {}).get("heap_max_in_bytes")
        if isinstance(b, int):
            out.append((n.get("name") or nid, b // 1048576))
    return out


def heap_report(stats):
    """The heap of every 5.0 indexer node and a WARNING per node below 4 GB (a warning, never a stop)."""
    rows = heap_lines(stats)
    if not rows:
        print("heap5: the 5.0 indexer's heap could not be read (no node in _nodes/stats/jvm)")
        return 0
    for name, mb in rows:
        if mb < HEAP_MIN_MB:
            print("WARNING heap5: indexer node %s has a %d MB heap, below 4 GB: the history load and the manager's own "
                  "modules meet the indexer's circuit breaker. Raise -Xms and -Xmx in /etc/wazuh-indexer/jvm.options of "
                  "that node to 4g or more (at most half its RAM; the host needs the RAM for it) and restart "
                  "wazuh-indexer before the history phase. Why: %s." % (name, mb, HEAP_WHY))
        else:
            print("heap5: indexer node %s has a %d MB heap (4 GB or more)" % (name, mb))
    return 0


def heap5():
    """R1 extra item 10, after the install: the heap the 5.0 indexer runs with (all-in-one replace gate)."""
    code, d = idx("GET", "/_nodes/stats/jvm?filter_path=nodes.*.name,nodes.*.jvm.mem.heap_max_in_bytes", idx_password5())
    if code != 200:
        print("heap5: the 5.0 indexer did not answer _nodes/stats/jvm (HTTP %s): heap not checked" % code)
        return 0
    return heap_report(d)


def decisions_section(action, path, section, other):
    """The flow's decisions file (MIGRATION_DECISIONS) and a tool's own decisions file: `get` writes the section to
    `other` (exit 1 when it is empty), `put` copies `other` into the section with every answer it already holds kept."""
    d = load(os.path.dirname(path) or ".", os.path.basename(path)) or {}
    if action == "get":
        sec = d.get(section)
        if not sec:
            return 1
        with open(other, "w") as f:
            json.dump(sec, f, indent=1)
        return 0
    new = json.load(open(other))
    old = d.get(section)
    d[section] = old if old else new
    write(os.path.dirname(path) or ".", os.path.basename(path), d)
    print("decisions: the %s questions are in %s, section \"%s\"" % (section, os.environ.get("DECISIONS_SHOWN") or path, section))
    return 0

# ------------------------------------------------------------------------------------------------ rule 14: the feed
_FEED_RX = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) .*content-updater.*(Starting feed download|Slice \d+ \(\d+/\d+\) in progress)")


# this build logs the end of the initial load (E2-deb evidence 20-bundle-b/11-rule14-feed-lines.txt):
# "... vulnerability-scanner: INFO: CVE feed fully loaded — per-agent scans unblocked." (the content updater's
# "Initial load download phase complete" comes the same second)
_FEED_DONE_RX = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) .*vulnerability-scanner.*CVE feed fully loaded")
# after a complete load, a manager restart logs "Starting feed download" again,
# then an incremental update from the stored cursor and the scanner's "Feed update process completed (changed=false)",
# never "CVE feed fully loaded" again. That line also ends the
# initial load (changed=true, the same second as "CVE feed fully loaded"). It counts as the completion
# only when this load is one of those two: an incremental update ("Starting incremental update from offset", which the
# updater starts only from a complete local database) or an initial load whose download phase completed. A database
# found incomplete or missing at startup, or an interrupted download, starts a full load again: then only its own
# completion counts, so a first load still running is never taken as loaded.
_FEED_UPDATE_DONE_RX = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) .*vulnerability-scanner.*Feed update process completed")
_FEED_INCR_RX = re.compile(r"content-updater.*(Starting incremental update from offset|Initial load download phase complete)")
_FEED_RESET_RX = re.compile(r"(vulnerability-scanner.*(local feed database is incomplete at startup|No existing local vulnerability feed)"
                            r"|content-updater.*(Initial load download phase interrupted|Initial load interrupted))")


def feed_load_state(lines, now_s, quiet_s=180):
    """Rule 14: the vulnerability feed's load, read from the manager log. 'loading' while the content
    updater wrote a 'Starting feed download' or 'Slice … in progress' line in the last quiet_s seconds (a manager restart
    then discards the load and no upgraded agent's packages, OS or vulnerabilities synchronise until a load completes);
    'quiet' when it wrote such lines earlier and none recently; 'unknown' when there is none. 'quiet' is an inference,
    not a proof. 'complete' when a completion line comes after the last progress line (a later download starts a new
    load): the scanner's 'CVE feed fully loaded', or its 'Feed update process completed' for a load that is
    an incremental update from a complete database or an initial load whose download completed."""
    last = done = None
    resumable = False          # this load continues a complete database, or its initial download completed
    for line in lines:
        m = _FEED_RX.match(line)
        if m:
            last = m.group(1)
            if "Starting feed download" in line:
                resumable = False
        if _FEED_RESET_RX.search(line):
            resumable, done = False, None
        elif _FEED_INCR_RX.search(line):
            resumable = True
        d = _FEED_DONE_RX.match(line)
        if d:
            done = d.group(1)
        u = _FEED_UPDATE_DONE_RX.match(line)
        if u and resumable:
            done = u.group(1)
    if done and (last is None or done >= last):
        return "complete", done
    if last is None:
        return "unknown", None
    t = time.mktime(time.strptime(last, "%Y/%m/%d %H:%M:%S"))      # the manager writes local time
    return ("loading" if now_s - t < quiet_s else "quiet"), last


def feed_status(log_path="/var/wazuh-manager/logs/wazuh-manager.log"):
    try:
        st, last = feed_load_state(open(log_path, errors="replace"), time.time())
    except OSError as e:
        print(f"feed-status: cannot read {log_path}: {e}")
        return 2
    msg = {"loading": "the vulnerability feed's initial load is IN PROGRESS (last progress line %s): a manager restart now "
                      "discards it, and inventory and vulnerabilities of upgraded agents appear only after a complete load",
           "complete": "the vulnerability feed's load is complete (the scanner logged its completion line at %s)",
           "quiet": "no feed-load progress since %s and no completion line yet (inferred complete, not proven)",
           "unknown": "no feed-load line in the manager log%s"}[st] % (last or "")
    print("feed-status: " + msg)
    return 1 if st == "loading" else 0

_VD_OFF_RX = re.compile(r"<vulnerability-detection>(?:(?!</vulnerability-detection>).)*<enabled>\s*no\s*</enabled>", re.S)


def vd_disabled(conf_path):
    """True when the 5.0 manager's configuration turns vulnerability detection off: no feed is then loaded."""
    try:
        with open(conf_path, errors="replace") as f:
            return bool(_VD_OFF_RX.search(f.read()))
    except OSError:
        return False


def feed_wait(log_path="/var/wazuh-manager/logs/wazuh-manager.log", max_s="3600", conf_path="", poll_s="30",
              _now=time.time, _sleep=time.sleep):
    """Rule 14 (decision of 2026-11-24: wait for the feed): block until the scanner logs a completion line after the last load
    started ('CVE feed fully loaded', or 'Feed update process completed' for an incremental update or a completed initial
    download: feed_load_state; E3 fold, N7: a restart after a complete load logs only the second). A restart during the initial load throws it away and upgraded agents send no packages,
    OS or vulnerabilities until a load completes, so phase 10 waits before its gate and the finish before its restart.
    'quiet' (progress stopped, no completion line) keeps waiting: only the completion line proves the load. Exit 0 when
    complete or when vulnerability detection is off; 1 at max_s, naming how to go on without it."""
    # E4-deb N-F1a: one line at a time into the step's log (block-buffered into a file, 18 minutes of wait showed nothing)
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    max_s, poll_s = int(max_s), int(poll_s)
    if conf_path and vd_disabled(conf_path):
        print("feed-wait: vulnerability detection is off in %s: no feed to wait for" % conf_path)
        return 0
    t0, shown = _now(), None
    while True:
        try:
            with open(log_path, errors="replace") as f:
                st, last = feed_load_state(f, _now())
        except OSError as e:
            st, last = "unreadable", str(e)
        if st == "complete":
            print("feed-wait: the vulnerability feed's load is complete (the scanner logged its completion line at %s), "
                  "after %d s of waiting" % (last, _now() - t0))
            return 0
        if st != shown:
            print("feed-wait: %s%s; waiting up to %d s for the scanner's completion line" % (st, " (last line %s)" % last if last else "", max_s))
            shown = st
        if _now() - t0 >= max_s:
            print("feed-wait: NOT LOADED after %d s (state: %s). Packages, OS and vulnerabilities of upgraded agents stay empty "
                  "until it loads, and a manager restart now starts it again. Check that the manager reaches the CTI feed; "
                  "to go on without it, rerun with FEED_WAIT_MAX=0 (the step then only reports the state)" % (max_s, st))
            return 1
        _sleep(poll_s)


# ------------------------------------------------------------------------------------------------ rule 8: in force
_SYNC_RX = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) .*Successfully synchroni[sz]ed space '([^']+)'")


def synced_spaces(lines, since):
    """{space: first time it logged 'Successfully synchronized space' at or after `since`} from manager log lines.
    `since` is the manager log's own 'YYYY/MM/DD HH:MM:SS' (the decision's time); a line at the same second counts."""
    got = {}
    for line in lines:
        m = _SYNC_RX.match(line)
        if m and m.group(1) >= since and m.group(2) not in got:
            got[m.group(2)] = m.group(1)
    return got


def wait_in_force(since, spaces, secs="300", log_path="/var/wazuh-manager/logs/wazuh-manager.log"):
    """F6-D3 (rule 8): the decision on unclassified events is applied to a running manager; the engine takes it only at
    its next synchronisation of each space it changed (54 to 89 s measured). Restarting to open the listeners before
    that starts the engine on its cached policy, and the events agents flush in the next 4 to 7 s run under the old one
    (F6: 42 of 42 Windows event-log lines lost). Wait for every changed space to log its synchronisation after the
    decision; only then may the opening restart run. spaces: comma-separated (standard, custom); empty: nothing changed."""
    want = [x for x in spaces.split(",") if x]
    if not want:
        print("wait-in-force: the decision changed no policy space; nothing to wait for")
        return 0
    t_end = time.time() + int(secs)
    while True:
        try:
            got = synced_spaces(open(log_path, errors="replace"), since)
        except OSError as e:
            print(f"wait-in-force: cannot read {log_path}: {e}")   # rule 19: an unreadable gate input stops the run
            return 1
        missing = [x for x in want if x not in got]
        if not missing:
            print("wait-in-force: the engine synchronised %s after the decision at %s: in force before the opening restart" % (
                ", ".join("%s at %s" % (x, got[x]) for x in want), since))
            return 0
        if time.time() > t_end:
            print(f"wait-in-force: space(s) {missing} not synchronised within {secs}s after {since}: the listeners stay closed")
            return 1
        time.sleep(5)

def wpk_repo(manifest):
    """CL1: the agent upgrade package repository a development build's artifact_urls.yaml names: every wazuh_wpk_* entry
    must share the prefix before its platform part (linux/, windows/, macos/), else none is printed (exit 1). The cluster's
    fleet step uses it when WPK_REPO is not set; a published release has no manifest and keeps the manager's default."""
    bases = set()
    for line in open(manifest, errors="replace"):
        m = re.match(r'^\s*wazuh_wpk_[A-Za-z0-9_]+:\s*"?([^"\s]+)"?\s*$', line)
        if m:
            u = m.group(1)
            k = min([u.find(p) for p in ("/linux/", "/windows/", "/macos/") if u.find(p) > 0] or [-1])
            if k < 0:
                print("wpk-repo: an entry without a linux/, windows/ or macos/ part: %s" % u, file=sys.stderr)
                return 1
            bases.add(u[:k + 1].split("://", 1)[-1])
    if len(bases) != 1:
        print("wpk-repo: %s" % ("no wazuh_wpk_* entry in %s" % manifest if not bases else "several repositories: %s" % sorted(bases)), file=sys.stderr)
        return 1
    print(bases.pop())
    return 0


if __name__ == "__main__":
    cmd, args = (sys.argv[1] if len(sys.argv) > 1 else ""), sys.argv[2:]
    fn = {"truth4": truth4, "fingerprint": fingerprint, "export-saved-objects": export_saved_objects,
          "export-security-rest": export_security_rest, "bundle-ids": bundle_ids, "setup-status": setup_status,
          "handshake": handshake, "reconcile-membership": reconcile_membership, "import-security": import_security,
          "import-saved-objects": import_saved_objects, "policy-unclassified": policy_unclassified, "truth5": truth5,
          "compare": compare, "wait-agents": wait_agents, "wait-in-force": wait_in_force, "agent-registry": agent_registry, "feed-status": feed_status, "feed-wait": feed_wait, "group-versions": group_versions, "retention-4x": retention_4x, "ism-restore4": ism_restore4, "source-version": source_version, "source-version-cluster": source_version_cluster, "v4-assistant-check": v4_assistant_check,
          "decisions-section": decisions_section, "wpk-repo": wpk_repo, "settle-agents": settle_agents, "raw-decision": raw_decision, "raw-facts": raw_facts_cmd,
          "rmig-check": rmig_check, "ruleset-review": ruleset_review, "ruleset-answers-differ": ruleset_answers_differ, "ruleset-open": ruleset_open, "ruleset-merge": ruleset_merge, "ruleset-carry": ruleset_carry, "ruleset-hints": ruleset_hints, "node-carry": node_carry,
          "rmig-outcome": rmig_outcome, "heap5": heap5,
          "rollback-saved-objects": rollback_saved_objects}.get(cmd)
    if not fn:
        sys.exit(__doc__)
    sys.exit(fn(*args) or 0)
