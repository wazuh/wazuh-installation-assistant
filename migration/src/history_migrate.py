#!/usr/bin/env python3
"""history_migrate.py - arm S4 copy of arm S2's s2_migrate.py. Same document shape, pipeline and logic; the only additions
are --tag (suffix of the template, pipeline, script and policy names), --main-prefix / --cloud-prefix (target index
names, so the same data can be placed inside or outside the findings name space) and --months (migrate a subset).

Original description (arm S2): put Wazuh 4.x alerts into ordinary indices that the stock 5.0 modules already read.

Source: 4.x alert indices already present in the 5.0 indexer (wazuh-alerts-4.x-YYYY.MM.DD, e.g. restored from a
snapshot). Target, one index per month and family:

    wazuh-findings-v5-legacy-4x-YYYY.MM                    everything except cloud-services
    wazuh-findings-v5-cloud-services-legacy-4x-YYYY.MM     AWS, Azure, GCP, Office 365, GitHub
                                                           (those modules read wazuh-findings-v5-cloud-services*)

Each target document is:
    WCS fields (wazuh.*, event.*, file.*, source.*, ...) typed exactly as the installed findings template types them,
    tags: ["v4-legacy"]                        the marker,
    legacy.index, legacy.id                    where the alert came from,
    legacy.alert.*                             the complete, unmodified 4.x alert with its 4.x mapping.
Target _id = "<source index>:<source _id>", so merging daily indices cannot overwrite a document.

    s2_migrate.py apply    [--retention 365d] [--cluster-name NAME]
    s2_migrate.py verify
    s2_migrate.py rollback --yes

Python 3 standard library only. Connection options as in fixture/truth/compare.py.
"""
import argparse
import base64
import calendar
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse

TEMPLATE = "wazuh-legacy-4x-history"
PIPELINE = "wazuh-legacy-4x-history"
POLICY = "wazuh-legacy-4x-retention"
MAIN_PREFIX = "wazuh-findings-v5-legacy-4x-"
CLOUD_PREFIX = "wazuh-findings-v5-cloud-services-legacy-4x-"
PATTERNS = [MAIN_PREFIX + "*", CLOUD_PREFIX + "*"]
ALL = ",".join(PATTERNS)
FINDINGS_TEMPLATE = "wazuh-findings-v5-system-activity-template"
MARK = {"managed_by": "wazuh-migration-s2", "version": "0.1"}

# WCS field <- 4.x path (plain copies). Types come from the installed findings template at run time.
COPY = {
    "wazuh.agent.id": "agent.id", "wazuh.agent.name": "agent.name", "wazuh.agent.host.ip": "agent.ip",
    "wazuh.rule.id": "rule.id", "wazuh.rule.title": "rule.description", "wazuh.rule.description": "rule.description",
    "wazuh.rule.tags": "rule.groups", "wazuh.protocol.location": "location", "event.severity": "rule.level",
    "wazuh.rule.compliance.pci_dss": "rule.pci_dss", "wazuh.rule.compliance.gdpr": "rule.gdpr",
    "wazuh.rule.compliance.hipaa": "rule.hipaa", "wazuh.rule.compliance.nist_800_53": "rule.nist_800_53",
    "wazuh.rule.compliance.tsc": "rule.tsc",
    "wazuh.rule.mitre.technique.id": "rule.mitre.id", "wazuh.rule.mitre.technique.name": "rule.mitre.technique",
    "event.original": "full_log", "wazuh.integration.decoders": "decoder.name",
    "source.ip": "data.srcip", "source.port": "data.srcport", "destination.ip": "data.dstip",
    "destination.port": "data.dstport", "user.name": "data.dstuser",
    "source.geo.country_name": "GeoLocation.country_name", "source.geo.city_name": "GeoLocation.city_name",
    "source.geo.region_name": "GeoLocation.region_name", "source.geo.location": "GeoLocation.location",
    "file.path": "syscheck.path", "file.hash.md5": "syscheck.md5_after", "file.hash.sha1": "syscheck.sha1_after",
    "file.hash.sha256": "syscheck.sha256_after", "file.owner": "syscheck.uname_after",
    "file.group": "syscheck.gname_after", "file.uid": "syscheck.uid_after", "file.gid": "syscheck.gid_after",
    "file.inode": "syscheck.inode_after", "file.mode": "syscheck.perm_after", "file.size": "syscheck.size_after",
    "file.mtime": "syscheck.mtime_after",
}
# WCS field <- first 4.x path that has a value (module-specific; later entries win over COPY).
FIRST = {
    # AWS module: event.action, event.provider, cloud.account.id, cloud.region, source.ip
    "aws": {"event.provider": ["data.aws.source"], "cloud.account.id": ["data.aws.accountId", "data.aws.recipientAccountId"],
            "cloud.region": ["data.aws.region", "data.aws.awsRegion"],
            "event.action": ["data.aws.eventName", "data.aws.service.action.actionType", "data.aws.type", "data.aws.action"],
            "source.ip": ["data.aws.sourceIPAddress", "data.aws.source_ip_address",
                          "data.aws.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4",
                          "data.aws.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4", "data.srcip"]},
    # Azure module: event.action, event.outcome, cloud.service.name, wazuh.rule.name, event.category, source.ip
    "azure": {"event.action": ["data.ms-graph.activityOperationType", "data.ms-graph.detectorId", "data.azure.operationName"],
              "event.outcome": ["data.ms-graph.activityResult", "data.ms-graph.status"],
              "cloud.service.name": ["data.ms-graph.serviceSource", "data.ms-graph.resource"],
              "event.category": ["data.ms-graph.category"], "source.ip": ["data.ms-graph.ipAddress"],
              "user.id": ["data.ms-graph.userId"], "wazuh.rule.name": ["rule.description"]},
    # Google Cloud module: cloud.project.id, cloud.region, cloud.instance.id, event.category, event.action,
    # event.outcome, dns.question.name, dns.response_code
    "gcp": {"cloud.project.id": ["data.gcp.resource.labels.project_id"], "cloud.region": ["data.gcp.resource.labels.location"],
            "cloud.instance.id": ["data.gcp.jsonPayload.vmInstanceId"], "event.category": ["data.gcp.resource.type"],
            "event.action": ["data.gcp.jsonPayload.queryType"], "event.outcome": ["data.gcp.jsonPayload.responseCode"],
            "dns.question.name": ["data.gcp.jsonPayload.queryName"], "dns.response_code": ["data.gcp.jsonPayload.responseCode"],
            "source.ip": ["data.gcp.jsonPayload.sourceIP"]},
    # Office 365 module: event.type, user.id, event.action, event.provider, client.ip, event.outcome
    "o365": {"event.action": ["data.office365.Operation"], "user.id": ["data.office365.UserId"],
             "event.provider": ["data.office365.Subscription", "data.office365.Workload"],
             "client.ip": ["data.office365.ClientIP"], "event.outcome": ["data.office365.ResultStatus"],
             "event.type": ["data.office365.RecordType"]},
    # GitHub module: organization.name, user.name, event.action, url.original, source.ip
    "github": {"organization.name": ["data.github.org"], "user.name": ["data.github.actor"],
               "event.action": ["data.github.action"], "url.original": ["data.github.repo", "data.github.repository"]},
    # Docker module: event.action, event.category, container.image.name, container.name
    "docker": {"event.action": ["data.docker.Action", "data.docker.status", "data.docker.level"],
               "event.category": ["data.docker.Type"], "container.image.name": ["data.docker.Actor.Attributes.image"],
               "container.name": ["data.docker.Actor.Attributes.name"], "container.id": ["data.docker.Actor.ID", "data.docker.id"]},
}
# Fields the pipeline computes itself.
COMPUTED = ["@timestamp", "tags", "wazuh.cluster.name", "wazuh.cluster.node", "wazuh.rule.level",
            "wazuh.integration.name", "wazuh.integration.category", "wazuh.rule.mitre.tactic.name",
            "wazuh.rule.mitre.tactic.id", "event.action", "event.category", "event.type", "event.kind",
            "file.name", "file.directory"]
# Free text in 4.x that goes into a typed WCS field: keep the document, skip the value when it does not parse.
LENIENT = {"ip", "long", "date", "geo_point", "integer", "short", "double", "float"}

# 4.x rule.groups / decoder.name -> 5.0 integration name and category (first match wins). Not an official table.
INTEGRATIONS = [
    (("sca",), "wazuh-sca", "security"), (("rootcheck",), "wazuh-rootcheck", "security"),
    (("vulnerability-detector",), "wazuh-vd", "security"),
    (("docker", "docker-error"), "docker", "system-activity"),
    (("amazon", "aws"), "aws", "cloud-services"), (("gcp",), "gcp", "cloud-services"),
    (("azure", "ms-graph"), "azure", "cloud-services"), (("office365",), "o365", "cloud-services"),
    (("github",), "github", "cloud-services"),
    (("sysmon", "sysmon_event1"), "windows-sysmon", "system-activity"),
    (("windows_security", "windows", "win_evt_channel"), "windows-security", "system-activity"),
    (("osquery",), "osquery", "security"), (("oscap",), "openscap", "security"), (("ciscat",), "cis-cat", "security"),
    (("yara",), "yara", "security"), (("suricata", "ids"), "suricata", "security"),
    (("virustotal",), "virustotal", "security"),
    (("audit", "auditd"), "auditd", "system-activity"),
    (("apache", "web", "accesslog", "attack"), "apache-http", "applications"), (("nginx",), "nginx", "applications"),
    (("postfix", "sendmail", "courier", "imapd", "spam", "mailscanner"), "mail", "applications"),
    (("iptables", "firewall", "pix", "netscreenfw", "sonicwall", "cisco_ios", "firewall_drop"), "iptables", "network-activity"),
    (("ossec", "wazuh", "active_response"), "wazuh-manager", "system-activity"),
    (("sshd", "pam", "sudo", "su", "authentication_failed", "authentication_success", "authentication_failures",
      "invalid_login", "adduser", "useradd", "groupadd", "login"), "system-auth", "system-activity"),
    (("dpkg", "yum", "systemd", "config_changed", "syslog", "linuxkernel"), "linux", "system-activity"),
]
FALLBACK_INTEGRATION = ("legacy-4x", "unclassified")
# 4.x ATT&CK tactic name -> (name in the ATT&CK version 5.0 uses, id). 5.0 renamed Defense Evasion to Stealth.
TACTICS = {
    "Reconnaissance": ("Reconnaissance", "TA0043"), "Resource Development": ("Resource Development", "TA0042"),
    "Initial Access": ("Initial Access", "TA0001"), "Execution": ("Execution", "TA0002"),
    "Persistence": ("Persistence", "TA0003"), "Privilege Escalation": ("Privilege Escalation", "TA0004"),
    "Defense Evasion": ("Stealth", "TA0005"), "Credential Access": ("Credential Access", "TA0006"),
    "Discovery": ("Discovery", "TA0007"), "Lateral Movement": ("Lateral Movement", "TA0008"),
    "Collection": ("Collection", "TA0009"), "Exfiltration": ("Exfiltration", "TA0010"),
    "Command and Control": ("Command and Control", "TA0011"), "Impact": ("Impact", "TA0040"),
}

# Reindex script: wrap the untouched alert, record where it came from, make the id unique across source indices.
REINDEX_SCRIPT = """
Map orig = new HashMap(ctx._source);
ctx._source.clear();
ctx._source.legacy = ['index': ctx._index, 'id': ctx._id, 'alert': orig];
ctx._id = ctx._index + ':' + ctx._id;
"""

PAINLESS = r"""
Object g(def m, String p) {
  def c = m;
  for (String k : p.splitOnToken('.')) { if (!(c instanceof Map)) { return null; } c = ((Map) c).get(k); if (c == null) { return null; } }
  if (c instanceof String && ((String) c).length() == 0) { return null; }
  if (c instanceof Map && ((Map) c).isEmpty()) { return null; }
  return c;
}
void s(Map m, String p, def v) {
  if (v == null) { return; }
  String[] ks = p.splitOnToken('.'); Map c = m;
  for (int i = 0; i < ks.length - 1; i++) { if (!(c.get(ks[i]) instanceof Map)) { c.put(ks[i], new HashMap()); } c = (Map) c.get(ks[i]); }
  c.put(ks[ks.length - 1], v);
}
Map a = (Map) ((Map) ctx.legacy).alert;
def ts = a.get('@timestamp'); if (ts == null) { ts = a.get('timestamp'); }
ctx['@timestamp'] = ts;
ctx.tags = ['v4-legacy'];
for (def e : params.copy.entrySet()) { s(ctx, e.getKey(), g(a, e.getValue())); }
s(ctx, 'wazuh.cluster.name', params.cluster);
def node = g(a, 'cluster.node'); if (node == null) { node = g(a, 'manager.name'); }
s(ctx, 'wazuh.cluster.node', node);
s(ctx, 'event.kind', 'alert');
def rl = g(a, 'rule.level');
if (rl != null) {
  int l = -1;
  if (rl instanceof Number) { l = ((Number) rl).intValue(); } else { try { l = Integer.parseInt(rl.toString().trim()); } catch (NumberFormatException e) { l = -1; } }
  if (l >= 0) { s(ctx, 'wazuh.rule.level', l >= 15 ? 'critical' : l >= 12 ? 'high' : l >= 7 ? 'medium' : 'low'); }
}
def tn = g(a, 'rule.mitre.tactic');
if (tn != null) {
  List src = tn instanceof List ? (List) tn : [tn]; List names = new ArrayList(); List ids = new ArrayList();
  for (def n : src) {
    if (n == null) { continue; }
    def m = params.tactics.get(n.toString()); String nn = m != null ? m[0] : n.toString();
    if (!names.contains(nn)) { names.add(nn); if (m != null) { ids.add(m[1]); } }
  }
  s(ctx, 'wazuh.rule.mitre.tactic.name', names); if (!ids.isEmpty()) { s(ctx, 'wazuh.rule.mitre.tactic.id', ids); }
}
String iname = null; String icat = null;
if (a.get('syscheck') instanceof Map && g(a, 'syscheck.path') != null) {
  iname = 'wazuh-fim'; icat = 'system-activity';
  def ev = g(a, 'syscheck.event');
  Map act = ['added': 'created', 'modified': 'modified', 'deleted': 'deleted'];
  Map typ = ['added': 'creation', 'modified': 'change', 'deleted': 'deletion'];
  s(ctx, 'event.category', ['file']); s(ctx, 'event.action', act.getOrDefault(ev, ev)); s(ctx, 'event.type', [typ.getOrDefault(ev, 'info')]);
  String ps = g(a, 'syscheck.path').toString();
  int x = ps.lastIndexOf('/'); int y = ps.lastIndexOf('\\'); int i = x > y ? x : y;
  s(ctx, 'file.name', ps.substring(i + 1)); s(ctx, 'file.directory', i > 0 ? ps.substring(0, i) : ps.substring(0, i + 1));
} else {
  Set keys = new HashSet();
  def rg = g(a, 'rule.groups');
  if (rg instanceof List) { for (def x : rg) { if (x != null) { keys.add(x.toString()); } } } else if (rg != null) { keys.add(rg.toString()); }
  def dn = g(a, 'decoder.name'); if (dn != null) { keys.add(dn.toString()); }
  for (def m : params.imap) {
    boolean hit = false;
    for (def k : m.keys) { if (keys.contains(k)) { hit = true; break; } }
    if (hit) { iname = m.name; icat = m.cat; break; }
  }
  if (iname == null) { iname = params.fallback[0]; icat = params.fallback[1]; }
}
s(ctx, 'wazuh.integration.name', iname); s(ctx, 'wazuh.integration.category', icat);
if (params.first.containsKey(iname)) {
  for (def e : ((Map) params.first.get(iname)).entrySet()) {
    for (def p : e.getValue()) { def v = g(a, p); if (v != null) { s(ctx, e.getKey(), v); break; } }
  }
}
if (iname == 'docker' && g(ctx, 'event.category') == null) { s(ctx, 'event.category', ['application']); }
// Month comes from the reindex destination; cloud-services documents go to the family the cloud modules read.
if (icat == 'cloud-services' && ctx._index.startsWith(params.main)) { ctx._index = params.cloud + ctx._index.substring(params.main.length()); }
"""


class Api:
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


def out(m=""): print(m, flush=True)
def must(res, what):
    s, o = res
    if s not in (200, 201): raise SystemExit(f"ERROR {what}: HTTP {s} {json.dumps(o)[:800]}")
    return o


DAY = re.compile(r"(\d{4})\.(\d{2})\.(\d{2})$")


def groups(api, a):
    """{YYYY.MM: {"srcs": [...], "docs": n, "bytes": b, "cd": epoch ms of the end of the newest day}}"""
    o = must(api("GET", f"/_cat/indices/{a.source}?format=json&bytes=b&h=index,docs.count,pri.store.size,status&s=index"), "list sources")
    g = {}
    for x in o:
        m = DAY.search(x["index"])
        if not m or x.get("status") == "close": continue
        y, mo, d = m.groups()
        if a.months and f"{y}.{mo}" not in a.months.split(","): continue
        e = g.setdefault(f"{y}.{mo}", {"srcs": [], "docs": 0, "bytes": 0, "cd": 0})
        e["srcs"].append(x["index"]); e["docs"] += int(x["docs.count"] or 0); e["bytes"] += int(x["pri.store.size"] or 0)
        e["cd"] = max(e["cd"], calendar.timegm((int(y), int(mo), int(d), 23, 59, 59)) * 1000)
    return dict(sorted(g.items()))


def wcs_types(api):
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


def merge_props(a, b):
    for k, v in b.items():
        if k not in a: a[k] = v
        elif "properties" in a[k] and "properties" in v: merge_props(a[k]["properties"], v["properties"])


def build_template(api, a):
    types, fset = wcs_types(api)
    wanted = set(COPY) | set(COMPUTED) | {k for m in FIRST.values() for k in m}
    missing = sorted(w for w in wanted if w not in types)
    if missing: raise SystemExit(f"ERROR: not in the installed findings schema: {missing}")
    props = {}
    for w in sorted(wanted):
        leaf = dict(types[w])
        if leaf.get("type") in LENIENT: leaf["ignore_malformed"] = True
        put_path(props, w, leaf)
    # the 4.x mapping, whole, under legacy.alert
    src = must(api("GET", f"/{a.source}/_mapping"), "read source mappings")
    old, extra = {}, {}
    for idx in sorted(src):
        m = src[idx]["mappings"]; merge_props(old, m.get("properties", {}))
        for k in ("dynamic_templates", "date_detection", "numeric_detection"):
            if k in m and k not in extra: extra[k] = m[k]
    props["legacy"] = {"properties": {"index": {"type": "keyword"}, "id": {"type": "keyword"}, "alert": {"properties": old}}}
    first = sorted(src)[0]
    sset = must(api("GET", f"/{first}/_settings"), "source settings")[first]["settings"]["index"]
    df = list(fset.get("query", {}).get("default_field", []))
    df += ["legacy.alert." + f for f in sset.get("query", {}).get("default_field", [])]
    settings = {"index.number_of_shards": 1, "index.auto_expand_replicas": fset.get("auto_expand_replicas", "0-1"),
                "index.codec": fset.get("codec", "default"),
                "index.max_docvalue_fields_search": int(fset.get("max_docvalue_fields_search", 200)),
                "index.mapping.total_fields.limit": 10000, "index.query.default_field": df[:1000]}
    mappings = dict(extra); mappings.update({"dynamic": "true", "properties": props, "_meta": dict(MARK)})
    return {"index_patterns": PATTERNS, "priority": a.priority, "_meta": dict(MARK),
            "template": {"settings": settings, "mappings": mappings}}, len(wanted)


def pipeline_body(cluster):
    return {"description": "arm S2: 4.x alert (under legacy.alert) -> WCS fields. Removes nothing.",
            "processors": [{"script": {"lang": "painless", "source": PAINLESS, "params": {
                "copy": COPY, "cluster": cluster, "tactics": {k: list(v) for k, v in TACTICS.items()},
                "imap": [{"keys": list(k), "name": n, "cat": c} for k, n, c in INTEGRATIONS],
                "fallback": list(FALLBACK_INTEGRATION), "first": FIRST, "main": MAIN_PREFIX, "cloud": CLOUD_PREFIX}}}]}


def policy_body(a):
    # No ism_template: the indices carry the data date as creation date, and ISM only auto-attaches newer indices.
    return {"policy": {"description": f"arm S2: migrated 4.x alerts are deleted {a.retention} after the newest day they hold "
                                      "(index.creation_date is the data date).",
                       "default_state": "keep",
                       "states": [{"name": "keep", "actions": [],
                                   "transitions": [{"state_name": "delete", "conditions": {"min_index_age": a.retention}}]},
                                  {"name": "delete", "actions": [{"delete": {}}], "transitions": []}]}}


def count(api, idx, q=None):
    s, o = api("POST", f"/{idx}/_count?ignore_unavailable=true", {"query": q or {"match_all": {}}})
    return o.get("count", -1) if s == 200 else -1


def detect_cluster(api):
    s, o = api("POST", "/wazuh-findings-v5*,wazuh-events-v5*/_search",
               {"size": 0, "query": {"bool": {"must_not": [{"term": {"tags": "v4-legacy"}}]}},
                "aggs": {"c": {"terms": {"field": "wazuh.cluster.name", "size": 5}}}})
    b = o.get("aggregations", {}).get("c", {}).get("buckets", []) if s == 200 else []
    return b[0]["key"] if b else None


def cmd_apply(api, a):
    T0 = time.time()
    g = groups(api, a)
    if not g: raise SystemExit(f"no source index matches {a.source}")
    total = sum(x["docs"] for x in g.values())
    out(f"source {a.source}: {sum(len(x['srcs']) for x in g.values())} indices, {total:,} documents -> {len(g)} months")
    h = must(api("GET", "/_cluster/health"), "health")
    lim = 1000 * h.get("number_of_data_nodes", 1)
    out(f"shards today {h['active_shards']}, the history adds at most {2 * len(g)}; limit {lim}")
    cluster = a.cluster_name or detect_cluster(api)
    if not cluster: raise SystemExit("cannot tell the 5.0 cluster name (no native document); pass --cluster-name")
    out(f"wazuh.cluster.name for the history: {cluster}")
    body, n = build_template(api, a)
    must(api("PUT", f"/_index_template/{TEMPLATE}", body), "PUT template")
    out(f"template {TEMPLATE}: priority {a.priority}, patterns {PATTERNS}, {n} WCS fields + legacy.*")
    must(api("PUT", f"/_ingest/pipeline/{PIPELINE}", pipeline_body(cluster)), "PUT pipeline")
    must(api("PUT", "/_scripts/" + PIPELINE + "-wrap", {"script": {"lang": "painless", "source": REINDEX_SCRIPT}}), "PUT script")
    s, o = api("GET", f"/_plugins/_ism/policies/{POLICY}")
    q = f"?if_seq_no={o['_seq_no']}&if_primary_term={o['_primary_term']}" if s == 200 else ""
    must(api("PUT", f"/_plugins/_ism/policies/{POLICY}{q}", policy_body(a)), "PUT policy")
    out(f"pipeline {PIPELINE}, policy {POLICY} ({a.retention} from the data date)")
    for month, x in g.items():
        main, cloud = MAIN_PREFIX + month, CLOUD_PREFIX + month
        have = count(api, f"{main},{cloud}")
        if have == x["docs"]:
            out(f"  {month}: already complete ({have:,})")
        else:
            for dst in (main, cloud):
                if api("HEAD", f"/{dst}")[0] != 200:
                    # auto_manage false: the stock stream-findings-policy has an ism_template for wazuh-findings-v5* and
                    # would attach itself to any index of this name created after its last_updated_time.
                    must(api("PUT", f"/{dst}", {"settings": {"index.creation_date": x["cd"], "index.refresh_interval": "-1",
                                                             "index.plugins.index_state_management.auto_manage": False}}), f"create {dst}")
                else:   # an interrupted run left it write-blocked or not: open it for the rerun
                    api("PUT", f"/{dst}/_settings", {"index.blocks.write": False})
            t1 = time.time()
            s, o = api("POST", "/_reindex?wait_for_completion=true&refresh=true&timeout=10m",
                       {"conflicts": "proceed", "source": {"index": ",".join(x["srcs"]), "size": a.batch},
                        "dest": {"index": main, "pipeline": PIPELINE, "op_type": "create"},
                        "script": {"id": PIPELINE + "-wrap"}}, timeout=3600)
            if s != 200 or o.get("failures"):
                raise SystemExit(f"ERROR reindex {month}: HTTP {s} {json.dumps(o)[:1500]}. Rerun apply: it resumes.")
            api("POST", f"/{main},{cloud}/_refresh")
            have = count(api, f"{main},{cloud}")
            out(f"  {month}: {o.get('created', 0):,} created, {o.get('version_conflicts', 0):,} already there, "
                f"{have:,}/{x['docs']:,} in {time.time() - t1:.1f}s")
            if have != x["docs"]: raise SystemExit(f"ERROR {month}: {have} documents, source has {x['docs']}. Rerun apply.")
        for dst in (main, cloud):
            if api("HEAD", f"/{dst}")[0] != 200: continue
            if count(api, dst) == 0:
                api("DELETE", f"/{dst}"); continue
            api("PUT", f"/{dst}/_settings", {"index.refresh_interval": "5s"})
            if a.forcemerge: api("POST", f"/{dst}/_forcemerge?max_num_segments=1", timeout=3600)
            must(api("PUT", f"/{dst}/_settings", {"index.blocks.write": True}), f"write block {dst}")
            s, ex = api("GET", f"/_plugins/_ism/explain/{dst}")
            cur = (ex.get(dst) or {}).get("index.plugins.index_state_management.policy_id") if s == 200 else None
            if cur and cur != POLICY: api("POST", f"/_plugins/_ism/remove/{dst}")
            if cur != POLICY: api("POST", f"/_plugins/_ism/add/{dst}", {"policy_id": POLICY})
    out(f"apply finished in {time.time() - T0:.1f}s ({total / max(time.time() - T0, 0.001):,.0f} docs/s end to end)")
    return cmd_verify(api, a)


def cmd_verify(api, a):
    g = groups(api, a); fails = 0
    def check(ok, good, bad):
        nonlocal fails
        out(("  ok   " + good) if ok else ("  FAIL " + bad)); fails += 0 if ok else 1
    o = must(api("GET", f"/_cat/indices/{ALL}?format=json&bytes=b&h=index,docs.count,pri.store.size,pri,creation.date.string&s=index"), "list targets")
    tot = sum(int(x["docs.count"] or 0) for x in o); src = sum(x["docs"] for x in g.values())
    for x in o: out(f"       {x['index']:55s} {int(x['docs.count']):>8,} docs  {int(x['pri.store.size'])/1048576:8.1f} MB  created {x['creation.date.string']}")
    if g: check(tot == src, f"documents: {tot:,} = source {src:,}", f"documents: {tot:,}, source {src:,}")
    else: out(f"       (no source left to compare; {tot:,} documents in the history)")
    for q, name in (({"term": {"tags": "v4-legacy"}}, "tags:v4-legacy"), ({"exists": {"field": "legacy.id"}}, "legacy.id"),
                    ({"exists": {"field": "wazuh.cluster.name"}}, "wazuh.cluster.name"),
                    ({"exists": {"field": "wazuh.integration.name"}}, "wazuh.integration.name"),
                    ({"exists": {"field": "wazuh.rule.level"}}, "wazuh.rule.level"), ({"exists": {"field": "@timestamp"}}, "@timestamp")):
        n = count(api, ALL, q); check(n == tot, f"{name} on all {n:,}", f"{name} on {n:,} of {tot:,}")
    st = must(api("GET", f"/{ALL}/_settings/index.blocks.*,index.max_docvalue_fields_search?flat_settings=true"), "settings")
    check(all(v["settings"].get("index.blocks.write") == "true" for v in st.values()), "index.blocks.write on all", "an index is not write-blocked")
    check(not any(v["settings"].get("index.blocks.read_only") == "true" for v in st.values()), "no index.blocks.read_only", "read_only is set: ISM will fail")
    check(all(int(v["settings"].get("index.max_docvalue_fields_search", 100)) >= 200 for v in st.values()), "max_docvalue_fields_search >= 200", "docvalue limit below 200")
    for _ in range(30):     # _ism/add is asynchronous
        s, ex = api("GET", f"/_plugins/_ism/explain/{ALL}")
        pol = {k: v.get("index.plugins.index_state_management.policy_id") for k, v in ex.items() if isinstance(v, dict)}
        if pol and all(p == POLICY for p in pol.values()): break
        time.sleep(3)
    check(pol and all(p == POLICY for p in pol.values()), f"ISM: all {len(pol)} indices on {POLICY}", f"ISM policies: {pol}")
    out("RESULT: " + ("OK" if not fails else f"{fails} check(s) failed"))
    return 1 if fails else 0


def cmd_rollback(api, a):
    if not a.yes:
        out("dry run (add --yes): would delete " + ALL + f", template {TEMPLATE}, pipeline {PIPELINE}, script, policy {POLICY}"); return 0
    o = must(api("GET", f"/_cat/indices/{ALL}?format=json&h=index"), "list")
    for x in o:
        idx = x["index"]
        api("PUT", f"/{idx}/_settings", {"index.blocks.read_only": False}); api("POST", f"/_plugins/_ism/remove/{idx}")
        s, r = api("DELETE", f"/{idx}"); out(f"  DELETE {idx}: {s}")
    for what, path in (("template", f"/_index_template/{TEMPLATE}"), ("pipeline", f"/_ingest/pipeline/{PIPELINE}"),
                       ("script", f"/_scripts/{PIPELINE}-wrap"), ("policy", f"/_plugins/_ism/policies/{POLICY}")):
        s, r = api("DELETE", path); out(f"  {what}: {s}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["apply", "verify", "rollback"])
    ap.add_argument("--source", default="wazuh-alerts-4.x-*")
    ap.add_argument("--retention", default="365d")
    ap.add_argument("--cluster-name", help="wazuh.cluster.name of the 5.0 deployment (default: read from native documents)")
    ap.add_argument("--priority", type=int, default=500)
    ap.add_argument("--batch", type=int, default=500)
    ap.add_argument("--no-forcemerge", dest="forcemerge", action="store_false")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--url", default="https://127.0.0.1:9200"); ap.add_argument("--user", default="admin")
    ap.add_argument("--password"); ap.add_argument("--cacert"); ap.add_argument("--cert"); ap.add_argument("--key")
    ap.add_argument("--resolve", action="append")
    ap.add_argument("--tag", default="", help="suffix for the template, pipeline, script and policy names")
    ap.add_argument("--main-prefix", default=MAIN_PREFIX); ap.add_argument("--cloud-prefix", default=CLOUD_PREFIX)
    ap.add_argument("--months", help="comma-separated YYYY.MM to migrate (default: all)")
    a = ap.parse_args()
    g = globals()
    if a.tag:
        for k in ("TEMPLATE", "PIPELINE", "POLICY"): g[k] = g[k] + "-" + a.tag
    g["MAIN_PREFIX"], g["CLOUD_PREFIX"] = a.main_prefix, a.cloud_prefix
    g["PATTERNS"] = [a.main_prefix + "*", a.cloud_prefix + "*"]; g["ALL"] = ",".join(g["PATTERNS"])
    sys.exit({"apply": cmd_apply, "verify": cmd_verify, "rollback": cmd_rollback}[a.cmd](Api(a), a))


if __name__ == "__main__":
    main()
