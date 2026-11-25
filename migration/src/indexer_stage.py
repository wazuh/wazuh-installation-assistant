#!/usr/bin/env python3
"""indexer_stage.py - Wazuh 4.x -> 5.0 migration tool, stage `indexer`: the indexer's own configuration and security.

    indexer_stage.py export --bundle DIR  <4.x connection>  [--local CMD] [--conf-dir DIR] [--home DIR]
    indexer_stage.py import --bundle DIR  <5.0 connection>  [--dry-run] [--grant-states]
    indexer_stage.py verify --bundle DIR  <5.0 connection>

Connection: --url https://HOST:9200 --cacert CA --cert ADMIN.pem --key ADMIN-key.pem [--resolve HOST:PORT:IP].
The admin certificate is required on both sides: only it can read the security index (users' password hashes,
authentication backends) on 4.x and change security objects on 5.0.

export   reads the LIVE configuration (security index, cluster and node settings, JVM arguments, keystore entry names,
         notification channels, and the opensearch.yml / jvm.options files through --local), classifies each item as
         stock or custom against stock-4.14.10.json, and writes DIR/indexer/.
import   creates on 5.0 every custom object: users with their 4.x hashes, action groups, tenants, roles with every
         permission that covered the 4.x alerts rewritten for the history and the native findings (see translate_*),
         mappings, users added to stock mappings, authentication backends, notification channels, dynamic settings 5.0
         knows. It never changes a 5.0 object it did not create: those are refused and reported. Reruns are idempotent
         (DIR/indexer/import-state.json records a digest of what it wrote).
verify   compares 5.0 with what import planned (hashes included) and writes the report.

Every item ends in DIR/indexer/report.json and report.md as carried / changed / dropped / left to the user, with why.
Python 3 standard library only.
"""
import argparse
import base64
import datetime
import fnmatch
import hashlib
import http.client
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
TYPES = ["config", "internalusers", "roles", "rolesmapping", "actiongroups", "tenants", "nodesdn", "allowlist", "audit"]
OBJ_TYPES = ["actiongroups", "tenants", "roles", "internalusers", "rolesmapping"]     # import order
MARK = "[migrated from Wazuh 4.x]"
LEGACY_TAG = "v4-legacy"
FINDINGS = "wazuh-findings-v5*"                     # what the 5.0 modules read; holds the history through two aliases
SAMPLE_4X_ALERT = "wazuh-alerts-4.x-2026.01.01"
SAMPLE_5X_NAMES = ["wazuh-findings-v5-system-activity", "wazuh-findings-v5-legacy-4x", "wazuh-legacy-4x-alerts-2026.01"]
GONE_4X_FAMILIES = {"wazuh-monitoring-*": "5.0 has no monitoring indices (agent status is in the API and wazuh-states-*)",
                    "wazuh-statistics-*": "5.0 has no statistics indices (wazuh-metrics-* instead)",
                    "wazuh-archives-*": "4.x archives are not migrated; 5.0 raw events are wazuh-events-raw-v5*",
                    "wazuh-states-vulnerabilities-*": "rebuilt by 5.0 agents; the 5.0 index is wazuh-states-vulnerabilities*"}
# opensearch.yml keys the 4.x installer writes for the deployment itself; the 5.0 installer writes its own.
INSTALLER_KEYS = ["network.host", "node.name", "cluster.name", "cluster.initial_master_nodes", "cluster.initial_cluster_manager_nodes",
                  "node.max_local_storage_nodes", "path.data", "path.logs", "discovery.type", "discovery.seed_hosts",
                  "plugins.security.*", "bootstrap.memory_lock", "http.port", "transport.port", "node.master", "node.data",
                  "node.ingest", "node.roles", "cluster.routing.allocation.disk.threshold_enabled"]
# kept by the security plugin but meaningful to a migration: reported with the reason
SECURITY_KEYS_TO_REPORT = {"plugins.security.compliance.salt": "salt of masked fields: without the same salt, masked values on 5.0 differ from 4.x",
                           "plugins.security.restapi.roles_enabled": "who may use the security REST API",
                           "plugins.security.unsupported.restapi.allow_securityconfig_modification": "REST changes to authentication backends"}
NEVER_CARRY = {"path.repo": "5.0 already sets path.repo; a second definition stops the indexer (history track)",
               "compatibility.override_main_response_version": "removed in OpenSearch 3; was only there for Filebeat 7.10"}


# ------------------------------------------------------------------ HTTP
class Conn:
    def __init__(self, a):
        u = urllib.parse.urlparse(a.url)
        self.host, self.port = u.hostname, u.port or 9200
        self.addr = self.host
        for r in a.resolve or []:
            h, p, ip = r.split(":", 2)
            if h == self.host and int(p) == self.port:
                self.addr = ip
        self.ctx = ssl.create_default_context(cafile=a.cacert)
        if not a.cert:
            raise SystemExit("the admin certificate (--cert, --key) is required")
        self.ctx.load_cert_chain(a.cert, a.key)

    def __call__(self, method, path, body=None, ok=(200, 201)):
        data = None
        h = {}
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        for attempt in range(8):
            try:
                s = self.ctx.wrap_socket(socket.create_connection((self.addr, self.port), timeout=120), server_hostname=self.host)
                c = http.client.HTTPSConnection(self.host, self.port, timeout=120)
                c.sock = s
                c.request(method, path, body=data, headers=h)
                r = c.getresponse()
                raw = r.read()
                c.close()
            except OSError as e:
                if attempt == 7:
                    raise
                time.sleep(3)
                continue
            if r.status in (429, 503) and attempt < 7:
                time.sleep(2 + 2 * attempt)
                continue
            try:
                return r.status, (json.loads(raw) if raw else None)
            except ValueError:
                return r.status, raw.decode(errors="replace")


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def digest(o):
    return hashlib.sha256(canon(o).encode()).hexdigest()


def wjson(path, o):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(o, f, indent=1, sort_keys=True, ensure_ascii=False)


def rjson(path, default=None):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return default


class Report:
    def __init__(self, path):
        self.path, self.items = path, []

    def add(self, kind, name, outcome, why, **kw):
        assert outcome in ("carried", "changed", "dropped", "left to the user", "refused", "stock", "already there")
        self.items.append(dict(kind=kind, name=name, outcome=outcome, why=why, **kw))
        print(f"  {outcome:16} {kind}/{name}: {why}")

    def save(self, title):
        wjson(self.path + ".json", self.items)
        with open(self.path + ".md", "w") as f:
            f.write(f"# {title}\n\nGenerated {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}\n\n")
            counts = {}
            for i in self.items:
                counts[i["outcome"]] = counts.get(i["outcome"], 0) + 1
            f.write(", ".join(f"{v} {k}" for k, v in sorted(counts.items())) + "\n\n| Kind | Name | Outcome | Why |\n|---|---|---|---|\n")
            for i in self.items:
                f.write(f"| {i['kind']} | `{i['name']}` | {i['outcome']} | {i['why'].replace('|', '/')} |\n")


# ------------------------------------------------------------------ export
def read_security_index(conn):
    out = {}
    for t in TYPES:
        code, d = conn("GET", "/.opendistro_security/_doc/" + t)
        if code != 200:
            raise SystemExit(f"security index: {t}: HTTP {code} (is --cert the admin certificate?) {str(d)[:200]}")
        out[t] = json.loads(base64.b64decode(d["_source"][t]))
    return out


def local(a, cmd):
    pre = shlex.split(a.local) if a.local else []
    r = subprocess.run(pre + ["sh", "-c", cmd], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def yml_keys(text):
    """Top-level settings of opensearch.yml as flat keys (the file is flat in practice; nested blocks are flattened)."""
    keys, stack = {}, []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or line.lstrip().startswith("- "):
            continue
        ind = len(line) - len(line.lstrip())
        m = re.match(r"^\s*([^:#]+?)\s*:\s*(.*)$", line)
        if not m:
            continue
        while stack and stack[-1][0] >= ind:
            stack.pop()
        k = ".".join([s[1] for s in stack] + [m.group(1).strip().strip('"\'')])
        v = m.group(2).strip()
        if v == "":
            stack.append((ind, m.group(1).strip()))
            keys[k] = None
        else:
            keys[k] = v.strip('"\'')
    return keys


def classify_security(sec, rest_roles):
    stock = rjson(os.path.join(HERE, "stock-4.14.10.json"))
    res = {}
    for t in OBJ_TYPES:
        res[t] = {}
        for name, o in sec[t].items():
            if name == "_meta":
                continue
            flagged = bool(o.get("reserved") or o.get("hidden") or o.get("static"))
            if flagged or name in stock["names"].get(t, []):
                why = "flagged reserved/hidden/static" if flagged else "name shipped by 4.14.10"
                d = stock["digests"].get(t, {}).get(name)
                if d and d != digest(o):
                    res[t][name] = ("stock-modified", why + "; its content differs from what 4.14.10 ships")
                else:
                    res[t][name] = ("stock", why)
            else:
                res[t][name] = ("custom", "not shipped by 4.14.10")
    # static roles live in the plugin, not in the index: the REST API is the only place they appear
    for name, o in (rest_roles or {}).items():
        if isinstance(o, dict) and o.get("static") and name not in res["roles"]:
            res["roles"][name] = ("stock", "static role of the security plugin")
    # users a site added to a stock mapping
    adds = {}
    for name, o in sec["rolesmapping"].items():
        if name in stock["names"]["rolesmapping"]:
            extra = sorted(set(o.get("users", [])) - set(stock["mapping_users"].get(name, [])))
            if extra:
                adds[name] = {"users": extra, "backend_roles": o.get("backend_roles", []), "hosts": o.get("hosts", [])}
    return res, adds


def cmd_export(a):
    conn = Conn(a)
    out = os.path.join(a.bundle, "indexer")
    os.makedirs(out, exist_ok=True)
    code, root = conn("GET", "/")
    print(f"export: 4.x indexer {root.get('version', {}).get('number')} ({root.get('cluster_name')})")
    sec = read_security_index(conn)
    wjson(os.path.join(out, "security.json"), sec)
    code, rest_roles = conn("GET", "/_plugins/_security/api/roles")
    cls, adds = classify_security(sec, rest_roles if code == 200 else {})
    wjson(os.path.join(out, "classification.json"), {"objects": cls, "stock_mapping_additions": adds})
    for t in OBJ_TYPES:
        n = {k: sum(1 for v in cls[t].values() if v[0] == k) for k in ("custom", "stock", "stock-modified")}
        print(f"export: {t}: {n['custom']} custom, {n['stock']} stock, {n['stock-modified']} stock but modified")
    print(f"export: users added to stock mappings: {json.dumps(adds)}")
    # settings
    _, nodes = conn("GET", "/_nodes/_local/settings,jvm?flat_settings=true")
    node = next(iter(nodes["nodes"].values()))
    _, cluster = conn("GET", "/_cluster/settings?flat_settings=true")
    files = {}
    for f in ("opensearch.yml", "jvm.options"):
        rc, txt, err = local(a, f"cat {shlex.quote(a.conf_dir + '/' + f)}")
        files[f] = txt if rc == 0 else None
        print(f"export: {a.conf_dir}/{f}: {'read' if rc == 0 else 'NOT READ: ' + err.strip()[:120]}")
    rc, txt, err = local(a, f"OPENSEARCH_JAVA_HOME={a.home}/jdk OPENSEARCH_PATH_CONF={a.conf_dir} {a.home}/bin/opensearch-keystore list")
    ks = [l.strip() for l in txt.splitlines() if l.strip() and not l.startswith("/")] if rc == 0 else None
    print(f"export: keystore entries: {ks if ks is not None else 'NOT READ: ' + err.strip()[:200]}")
    code, notif = conn("GET", "/_plugins/_notifications/configs?max_items=1000")
    wjson(os.path.join(out, "settings.json"), {
        "node_settings": node.get("settings"), "jvm_input_arguments": node.get("jvm", {}).get("input_arguments"),
        "jvm_heap_max_bytes": node.get("jvm", {}).get("mem", {}).get("heap_max_in_bytes"),
        "cluster_settings": cluster, "opensearch_yml": files["opensearch.yml"], "jvm_options": files["jvm.options"],
        "keystore_entries": ks, "notifications": notif.get("config_list", []) if code == 200 else {"_error": code}})
    wjson(os.path.join(out, "export-info.json"), {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": root})
    print(f"export: written to {out}")


# ------------------------------------------------------------------ translation
def load_maps(a):
    """4.x field -> (native 5.0 field for a filter or None, every 5.0 field that may hold the value)."""
    m1 = rjson(a.field_map) if a.field_map and os.path.exists(a.field_map) else None
    spec = rjson(a.history_map) if a.history_map else None
    hist = dict((spec or {}).get("map", {}))
    if spec and spec.get("rules"):
        # Merged (H1 tool gap 2, S5-D1): the field-hiding map is generated from the loader's own table, never hand-made.
        # Union of the map builder's dependency index (`map`, what S5 proved: a restricted user read 0 hidden values)
        # and the fields convert() fills from each source (loader_map.field_hiding_map): FLS and masking hide every
        # 5.0 field that holds or is derived from a hidden 4.x field.
        sys.path.insert(0, HERE)
        import loader_map
        for f, tg in loader_map.field_hiding_map(spec).items():
            hist[f] = sorted(set(hist.get(f, [])) | set(tg))
    filt, hide = {}, {}
    if m1:
        rules = {r["id"]: r for r in m1["rules"]}
        for f, d in m1["source_dispositions"].items():
            tg = set(d.get("targets", []))
            hide.setdefault(f, set()).update(tg)
            same = [rules[r]["target"] for r in d.get("rule_ids", []) if r in rules
                    and rules[r]["operation"] in ("copy", "cast") and rules[r]["semantic"] == "same_meaning"]
            if len(same) == 1:
                filt[f] = same[0]
    if not m1 and spec and spec.get("rules"):
        # Merged (conflict C8): no separate M1 map; the filter translation comes from the corrected map the loader uses
        # (RD2's M3): a 4.x field translates for a filter on native findings only when exactly one same-meaning copy or
        # cast rule fills a 5.0 field from it, as C23 read it from M1's source_dispositions.
        same = {}
        for r in spec["rules"]:
            if r.get("operation") in ("copy", "cast") and r.get("semantic") == "same_meaning" and len(r.get("sources") or []) == 1:
                same.setdefault(r["sources"][0], set()).add(r["target"])
        filt.update({f: next(iter(t)) for f, t in same.items() if len(t) == 1})
    for f, tg in hist.items():
        hide.setdefault(f, set()).update(tg)
    global M1_OWNERS
    if m1:
        for f, d in m1["source_dispositions"].items():
            for t in d.get("targets", []):
                M1_OWNERS.setdefault(t, set()).add(f)
    return filt, {k: sorted(v) for k, v in hide.items()}


M1_OWNERS = {}


LEAF = {"term", "terms", "match", "match_phrase", "prefix", "wildcard", "range", "regexp", "fuzzy", "match_phrase_prefix"}


def rename_fields(q, fn):
    """Rewrite every field name in a query with fn(field) -> new name or None (untranslatable). Returns (q, missing)."""
    missing = []

    def walk(o, parent=None):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if parent in LEAF and not k.startswith("_") and k not in ("boost",):
                    n = fn(k)
                    if n is None:
                        missing.append(k)
                        n = k
                    out[n] = v
                elif k == "exists" and isinstance(v, dict) and "field" in v:
                    n = fn(v["field"])
                    if n is None:
                        missing.append(v["field"])
                    out[k] = dict(v, field=n or v["field"])
                elif k in ("query_string", "simple_query_string", "script", "has_child", "has_parent", "nested", "more_like_this", "terms_set"):
                    missing.append(f"<{k}>")
                    out[k] = v
                else:
                    out[k] = walk(v, k)
            return out
        if isinstance(o, list):
            return [walk(x, parent) for x in o]
        return o
    return walk(q), missing


def translate_dls(dls, filt):
    """One 5.0 filter that gives the history exactly the 4.x filter (on the preserved alert under legacy.alert.*) and
    the native findings the same filter on 5.0 field names. If a field has no native equivalent, native findings are
    not readable through this permission (reported)."""
    if "${" in dls:
        return None, "uses user attribute substitution; checked by hand", None
    try:
        q = json.loads(dls)
    except ValueError:
        return None, "not JSON", None
    hist, _ = rename_fields(q, lambda f: f if f.startswith("legacy.") else "legacy.alert." + f)
    nat, missing = rename_fields(q, lambda f: filt.get(f))
    tag = {"term": {"tags": LEGACY_TAG}}
    native = {"bool": {"must_not": [tag], "filter": [nat]}} if not missing else {"match_none": {}}
    new = {"bool": {"should": [{"bool": {"filter": [tag, hist]}}, native], "minimum_should_match": 1}}
    return json.dumps(new, separators=(",", ":")), None, missing


def translate_fields(fields, hide, masked=False):
    """FLS (exclude ~f or include f) and masked fields: the preserved alert, every 5.0 field the history loader or the
    field map puts that value in. Returns (new list, notes)."""
    out, notes = [], []
    for f in fields:
        neg = f.startswith("~")
        base = f[1:] if neg else f
        algo = ""
        if masked and "::" in base:
            base, algo = base.split("::", 1)
            algo = "::" + algo
        tg = ["legacy.alert." + base] + hide.get(base, [])
        if "*" in base:
            tg += [t for k, v in hide.items() if fnmatch.fnmatch(k, base) for t in v]
        if not hide.get(base) and "*" not in base:
            notes.append(f"{base}: no 5.0 field holds it in the map; only the preserved alert is covered")
        for t in hide.get(base, []):
            other = sorted(M1_OWNERS.get(t, set()) - {base})
            if other:
                notes.append(f"{'~' if neg else ''}{t} also covers {other} on native findings (field map), which the 4.x role did not "
                             f"{'mask' if masked else 'hide'}: this role sees less than on 4.x there")
        for t in sorted(set(tg)):
            out.append(("~" if neg else "") + t + algo)
    if fields and not any(x.startswith("~") for x in fields) and not masked:
        out += ["@timestamp", "tags", "legacy.index", "legacy.id", "wazuh.cluster.name", "wazuh.integration.*"]
        notes.append("include-list FLS: fields the 5.0 modules filter on were added (@timestamp, tags, wazuh.cluster.name, "
                     "wazuh.integration.*); check the modules with this role")
    return sorted(set(out)), notes


def matches_any(patterns, names):
    return any(fnmatch.fnmatch(n, p) for p in patterns for n in names)


def translate_role(name, role, filt, hide, grant_states):
    """Returns (new role body, changes[], problems[])."""
    new = {k: role[k] for k in ("cluster_permissions", "tenant_permissions", "description") if k in role}
    changes, problems, perms = [], [], []
    for ip in role.get("index_permissions", []):
        pats = ip.get("index_patterns", [])
        alerts = matches_any(pats, [SAMPLE_4X_ALERT])
        five = matches_any(pats, SAMPLE_5X_NAMES)
        for p in pats:
            for fam, why in GONE_4X_FAMILIES.items():
                if fnmatch.fnmatch(fam.rstrip("*") + "x", p) and not fnmatch.fnmatch(SAMPLE_4X_ALERT, p):
                    problems.append(f"pattern {p}: {why}")
        if not (alerts or five):
            perms.append(ip)
            continue
        e = {k: v for k, v in ip.items() if k not in ("dls", "fls", "masked_fields")}
        kept = [p for p in pats if matches_any([p], SAMPLE_5X_NAMES) or not matches_any([p], [SAMPLE_4X_ALERT])]
        if alerts and not five:
            e["index_patterns"] = sorted(set(kept + [FINDINGS]))
            changes.append(f"index patterns {pats} -> {e['index_patterns']} (the history and the native findings)")
        if ip.get("dls"):
            nd, err, missing = translate_dls(ip["dls"], filt)
            if err:
                problems.append(f"DLS not translated ({err}); permission NOT granted on 5.0: {ip['dls']}")
                continue
            e["dls"] = nd
            changes.append(f"DLS {ip['dls']} -> history: same filter on legacy.alert.*; native: "
                           + (f"no 5.0 field for {missing}, native findings not readable" if missing else "same filter on 5.0 fields"))
            if missing:
                problems.append(f"DLS fields {missing} have no 5.0 equivalent: this role reads no native finding until its filter is rewritten")
        if ip.get("fls"):
            e["fls"], notes = translate_fields(ip["fls"], hide)
            changes.append(f"FLS {ip['fls']} -> {e['fls']}")
            problems += notes
        if ip.get("masked_fields"):
            e["masked_fields"], notes = translate_fields(ip["masked_fields"], hide, masked=True)
            changes.append(f"masked {ip['masked_fields']} -> {e['masked_fields']}")
            problems += notes
        perms.append(e)
        if grant_states and alerts:
            s = {"index_patterns": ["wazuh-states-*"], "allowed_actions": ip.get("allowed_actions", ["read"])}
            if ip.get("dls"):
                _, nat_missing = rename_fields(json.loads(ip["dls"]), lambda f: filt.get(f))
                if nat_missing:
                    problems.append("--grant-states: DLS cannot be expressed on the state indices; not granted")
                    continue
                s["dls"] = json.dumps(rename_fields(json.loads(ip["dls"]), lambda f: filt.get(f))[0], separators=(",", ":"))
            if ip.get("fls") or ip.get("masked_fields"):
                problems.append("--grant-states: the role has FLS or masking written for alerts; state indices not granted")
                continue
            perms.append(s)
            changes.append("read on wazuh-states-* added (--grant-states), with the role's DLS on 5.0 fields")
    new["index_permissions"] = perms
    return new, changes, problems


# ------------------------------------------------------------------ import
BODY_FIELDS = {"actiongroups": ("allowed_actions", "type", "description"),
               "tenants": ("description",),
               "roles": ("cluster_permissions", "index_permissions", "tenant_permissions", "description"),
               "internalusers": ("hash", "backend_roles", "attributes", "description", "opendistro_security_roles"),
               "rolesmapping": ("backend_roles", "hosts", "users", "and_backend_roles", "description")}


def marked(desc):
    return (desc + " " if desc else "") + MARK


def norm(o):
    if isinstance(o, dict):
        o = {k: norm(v) for k, v in o.items()}
        return {k: v for k, v in o.items() if v not in (None, "", [], {})}
    if isinstance(o, list):
        return [norm(x) for x in o]
    return o


def comparable(kind, o):
    return norm({k: o.get(k) for k in BODY_FIELDS[kind]})


def cmd_import(a):
    conn = Conn(a)
    ind = os.path.join(a.bundle, "indexer")
    sec = rjson(os.path.join(ind, "security.json"))
    cl = rjson(os.path.join(ind, "classification.json"))
    st = rjson(os.path.join(ind, "settings.json"))
    state_path = os.path.join(ind, "import-state.json")
    state = rjson(state_path, {})
    rep = Report(os.path.join(ind, "report-import"))
    filt, hide = load_maps(a)
    code, root = conn("GET", "/")
    print(f"import: 5.0 indexer {root.get('version', {}).get('number')} ({root.get('cluster_name')}){' DRY RUN' if a.dry_run else ''}")
    live = read_security_index(conn)
    refused = 0

    def put(kind, name, body, why_changed=None):
        nonlocal refused
        key = f"{kind}/{name}"
        want = comparable(kind, body)
        have = live[kind].get(name)
        if have is not None:
            mine = state.get(key)
            if mine is None or mine != digest(comparable(kind, have)):
                rep.add(kind, name, "refused", "5.0 already has an object of this name that this tool did not create "
                        "(or it was changed after the tool wrote it); not overwritten")
                refused += 1
                return False
            if digest(want) == mine:
                rep.add(kind, name, "already there", "written by an earlier run, unchanged")
                return True
        if a.dry_run:
            rep.add(kind, name, "changed" if why_changed else "carried", (why_changed or "as on 4.x") + " (dry run)")
            return True
        code, d = conn("PUT", f"/_plugins/_security/api/{kind}/{urllib.parse.quote(name)}", body)
        if code not in (200, 201):
            rep.add(kind, name, "left to the user", f"5.0 refused it: HTTP {code} {json.dumps(d)[:200]}")
            return False
        # what 5.0 stored, for the ownership digest (the API does not return hashes; the index does)
        live[kind] = read_security_index(conn)[kind]
        state[key] = digest(comparable(kind, live[kind][name]))
        wjson(state_path, state)
        rep.add(kind, name, "changed" if why_changed else "carried", why_changed or "as on 4.x")
        return True

    for kind in OBJ_TYPES:
        for name, (c, why) in sorted(cl["objects"][kind].items()):
            if c == "stock":
                continue
            o = sec[kind][name]
            if c == "stock-modified":
                rep.add(kind, name, "left to the user", why + ": 5.0 ships its own stock objects; compare by hand")
                continue
            body = {k: o[k] for k in BODY_FIELDS[kind] if k in o and o[k] not in (None, "")}
            body["description"] = marked(o.get("description", ""))
            changed = None
            if kind == "roles":
                body, changes, problems = translate_role(name, dict(o, description=body["description"]), filt, hide, a.grant_states)
                changed = "; ".join(changes) if changes else None
                for p in problems:
                    rep.add("roles", name, "left to the user", p)
            if kind == "internalusers":
                if not o.get("hash"):
                    rep.add(kind, name, "left to the user", "no password hash in the 4.x security index")
                    continue
                changed = None
            put(kind, name, body, changed)
    # users added to stock mappings: create the mapping on 5.0 only if 5.0 has the role and no mapping of that name
    for role, add in sorted(cl["stock_mapping_additions"].items()):
        if role not in live["roles"] and role not in rest_static_roles(conn):
            rep.add("rolesmapping", role, "dropped", f"users {add['users']} were added to this stock 4.x mapping; 5.0 has no role {role}")
            continue
        body = {"users": add["users"], "backend_roles": [b for b in add["backend_roles"] if b], "description": marked("")}
        put("rolesmapping", role, body, f"stock 4.x mapping: only the users the site added ({add['users']}); 4.x backend roles {add['backend_roles']}")
    import_backends(a, conn, sec, live, state, state_path, rep)
    import_settings(a, conn, st, state, state_path, rep)
    rep.save("Indexer stage: import report")
    print(f"import: {len(rep.items)} item(s), {refused} refused; report {rep.path}.md")
    return 2 if refused else 0


def rest_static_roles(conn):
    code, d = conn("GET", "/_plugins/_security/api/roles")
    return {k for k, v in (d or {}).items() if isinstance(v, dict)} if code == 200 else set()


def import_backends(a, conn, sec, live, state, state_path, rep):
    """Authentication and authorization domains: added to the 5.0 config under their 4.x names; existing 5.0 domains
    are never changed. Files a domain references (certificates, truststores) are listed for the user."""
    c4 = sec["config"]["config"]["dynamic"]
    c5 = live["config"]["config"]
    changed = False
    for part in ("authc", "authz"):
        for name, dom in sorted(c4.get(part, {}).items()):
            typ = (dom.get("authentication_backend") or dom.get("authorization_backend") or {}).get("type")
            http_type = (dom.get("http_authenticator") or {}).get("type")
            if not dom.get("http_enabled") and not dom.get("transport_enabled"):
                continue                                   # disabled template, as shipped
            if typ in ("intern", "internal") and http_type in ("basic", None):
                continue                                   # the internal users database: 5.0 has its own
            key = f"config/{part}/{name}"
            have = c5["dynamic"].get(part, {}).get(name)
            if have is not None and digest(have) == digest(dom):
                rep.add("config", f"{part}/{name}", "already there", "5.0 has the same domain")
                continue
            if have is not None and (have.get("http_enabled") or have.get("transport_enabled")) and state.get(key) != digest(have):
                rep.add("config", f"{part}/{name}", "refused", "5.0 has an enabled domain of this name that this tool did not write; not changed")
                continue
            if http_type == "saml" and a.dashboard_public_url:
                cfgd = dom.get("http_authenticator", {}).get("config", {})
                if cfgd.get("kibana_url") and cfgd["kibana_url"] != a.dashboard_public_url:
                    rep.add("config", f"{part}/{name}", "changed", f"kibana_url {cfgd['kibana_url']} -> {a.dashboard_public_url} "
                            "(the IdP must also accept the new assertion consumer URL)")
                    dom = json.loads(json.dumps(dom))
                    dom["http_authenticator"]["config"]["kibana_url"] = a.dashboard_public_url
                    if have is not None and digest(have) == digest(dom):
                        rep.add("config", f"{part}/{name}", "already there", "5.0 has the same domain")
                        continue
            elif http_type == "saml":
                rep.add("config", f"{part}/{name}", "left to the user", "kibana_url stays the 4.x dashboard URL "
                        f"{dom.get('http_authenticator', {}).get('config', {}).get('kibana_url')}; pass --dashboard-public-url if 5.0's differs")
            ch = (dom.get("http_authenticator") or {}).get("challenge")
            later = sorted(n for n, o in c5["dynamic"].get(part, {}).items() if n != name and (o.get("http_enabled"))
                           and (o.get("order", 0) > dom.get("order", 0)))
            if part == "authc" and ch and later:
                rep.add("config", f"{part}/{name}", "refused",
                        f"a challenging {http_type} domain at order {dom.get('order')} would stop the chain before {later} on 5.0 "
                        "(seen on 4.x: every internal user, kibanaserver included, gets 401); give it the highest order and rerun")
                continue
            if part == "authc" and http_type in ("saml", "openid"):
                chall = sorted(n for n, o in c5["dynamic"]["authc"].items() if n != name and o.get("http_enabled")
                               and (o.get("http_authenticator") or {}).get("challenge"))
                if chall:
                    rep.add("config", f"{part}/{name}", "left to the user",
                            f"5.0 domains {chall} still challenge; for {http_type} logins in the dashboard set their challenge to false "
                            "(a 5.0 object this tool does not change)")
            c5["dynamic"].setdefault(part, {})[name] = dom
            state[key] = digest(dom)
            changed = True
            files = sorted({v for v in json.dumps(dom).split('"') if re.match(r"^/[\w./-]+\.(pem|crt|key|jks|p12|xml)$", v)})
            rep.add("config", f"{part}/{name}", "carried",
                    f"{typ or http_type} domain added to the 5.0 security config"
                    + (" (replaces the disabled 5.0 template of the same name)" if have is not None else "")
                    + (f"; files it reads must exist on every 5.0 node: {files}" if files else ""))
            if http_type in ("saml", "openid"):
                rep.add("config", f"{part}/{name}", "left to the user",
                        "the dashboard needs opensearch_security.auth.type and its own settings in opensearch_dashboards.yml")
    k4 = (c4.get("kibana") or {}).get("multitenancy_enabled", True)
    k5 = (c5["dynamic"].get("kibana") or {}).get("multitenancy_enabled", True)
    if k4 and not k5:
        rep.add("config", "kibana.multitenancy_enabled", "left to the user", "on in 4.x, false in the 5.0 security config: custom tenants "
                "need it true here and opensearch_security.multitenancy.enabled: true in opensearch_dashboards.yml (both 5.0 objects)")
    if changed and not a.dry_run:
        code, d = conn("PUT", "/_plugins/_security/api/securityconfig/config", {"dynamic": c5["dynamic"]})
        how = f"REST API HTTP {code}"
        if code == 403:
            # The REST endpoint is closed unless plugins.security.unsupported.restapi.allow_securityconfig_modification
            # is true, even for the admin certificate. securityadmin takes the config as JSON (JSON is YAML).
            doc = json.dumps({"_meta": {"type": "config", "config_version": 2}, "config": c5})
            tmp = "/tmp/wazuh-migrate-security-config.json"
            pre = shlex.split(a.local5) if a.local5 else []
            w = subprocess.run(pre + ["sh", "-c", f"umask 077; cat > {tmp}"], input=doc, capture_output=True, text=True)
            cd = a.certs_dir5
            r = subprocess.run(pre + ["sh", "-c", f"JAVA_HOME={a.home}/jdk {a.home}/plugins/opensearch-security/tools/securityadmin.sh "
                                      f"-f {tmp} -t config -cacert {cd}/root-ca.pem -cert {cd}/admin.pem -key {cd}/admin-key.pem "
                                      f"-icl -nhnv -h {a.securityadmin_host}; rc=$?; rm -f {tmp}; exit $rc"], capture_output=True, text=True)
            code = 200 if r.returncode == 0 and "Done with success" in r.stdout else 500
            how += f"; securityadmin -t config: {'Done with success' if code == 200 else (r.stdout + r.stderr)[-300:]}"
        if code not in (200, 201):
            rep.add("config", "securityconfig", "left to the user", f"5.0 refused the update: {how}")
            for k in [k for k in state if k.startswith("config/")]:
                state.pop(k)
        else:
            rep.add("config", "securityconfig", "carried", f"authentication domains written ({how})")
        wjson(state_path, state)


def import_settings(a, conn, st, state, state_path, rep):
    yml = yml_keys(st.get("opensearch_yml") or "")
    _, d5 = conn("GET", "/_cluster/settings?include_defaults=true&flat_settings=true")
    known = set(d5.get("defaults", {})) | set(d5.get("persistent", {})) | set(d5.get("transient", {}))
    _, n5 = conn("GET", "/_nodes/_local/settings?flat_settings=true")
    known |= set(next(iter(n5["nodes"].values()))["settings"])
    for k, v in sorted(yml.items()):
        if v is None:
            continue
        if k in SECURITY_KEYS_TO_REPORT:
            rep.add("setting", k, "left to the user", f"{SECURITY_KEYS_TO_REPORT[k]} (4.x value kept in the bundle)")
            continue
        if k in NEVER_CARRY:
            rep.add("setting", k, "dropped", NEVER_CARRY[k])
            continue
        if any(fnmatch.fnmatch(k, p) for p in INSTALLER_KEYS):
            continue
        if k not in known:
            rep.add("setting", k, "dropped", f"5.0 does not know this setting (value {v!r}); an unknown key in opensearch.yml stops the indexer")
            continue
        cur = d5.get("persistent", {}).get(k)
        key = f"setting/{k}"
        if cur is not None and str(cur) == v and state.get(key) == v:
            rep.add("setting", k, "already there", f"persistent {v}")
            continue
        if cur is not None and state.get(key) != str(cur):
            rep.add("setting", k, "refused", f"5.0 already has persistent {k}={cur!r}, not set by this tool")
            continue
        if a.dry_run:
            rep.add("setting", k, "carried", f"{v} (dry run)")
            continue
        code, d = conn("PUT", "/_cluster/settings", {"persistent": {k: v}})
        if code == 200:
            state[key] = v
            wjson(state_path, state)
            rep.add("setting", k, "carried", f"{v}: dynamic on 5.0, set as a persistent cluster setting (survives restarts, not in opensearch.yml)")
        else:
            reason = (d or {}).get("error", {}).get("reason", "") if isinstance(d, dict) else str(d)
            rep.add("setting", k, "left to the user", f"5.0 knows it but not as a dynamic setting ({reason[:160]}); add `{k}: {v}` "
                    "to /etc/wazuh-indexer/opensearch.yml on every node and restart")
    # JVM
    args = st.get("jvm_input_arguments") or []
    heap = [x for x in args if x.startswith(("-Xms", "-Xmx"))]
    filed = [l.strip() for l in (st.get("jvm_options") or "").splitlines() if l.strip().startswith(("-Xms", "-Xmx"))]
    rep.add("jvm", "heap", "left to the user", f"4.x ran with {heap} (jvm.options says {filed or 'nothing'}, the last argument wins); "
            "5.0 sizes its own heap: set it in /etc/wazuh-indexer/jvm.options if the host is the same")
    # keystore
    ks = [k for k in (st.get("keystore_entries") or []) if k != "keystore.seed"]
    for k in ks:
        rep.add("keystore", k, "left to the user", "the 4.x keystore tool lists names but cannot show values; add it on every 5.0 node with "
                f"`/usr/share/wazuh-indexer/bin/opensearch-keystore add {k}` then POST /_nodes/reload_secure_settings")
    # notification channels
    for c in st.get("notifications") or []:
        cid = c.get("config_id")
        code, d = conn("GET", f"/_plugins/_notifications/configs/{cid}")
        key = f"notifications/{cid}"
        if code == 200:
            rep.add("notifications", cid, "already there" if key in state else "refused",
                    "written by an earlier run" if key in state else "5.0 has a channel with this id")
            continue
        if a.dry_run:
            rep.add("notifications", cid, "carried", "(dry run)")
            continue
        code, d = conn("POST", "/_plugins/_notifications/configs", {"config_id": cid, "config": c["config"]})
        if code in (200, 201):
            state[key] = digest(c["config"])
            wjson(state_path, state)
        rep.add("notifications", cid, "carried" if code in (200, 201) else "left to the user",
                f"{c['config'].get('config_type')} channel" + ("" if code in (200, 201) else f": HTTP {code} {json.dumps(d)[:160]}"))


# ------------------------------------------------------------------ verify
def cmd_verify(a):
    conn = Conn(a)
    ind = os.path.join(a.bundle, "indexer")
    sec = rjson(os.path.join(ind, "security.json"))
    state = rjson(os.path.join(ind, "import-state.json"), {})
    live = read_security_index(conn)
    bad = 0
    for key, dg in sorted(state.items()):
        kind, name = key.split("/", 1)
        if kind in OBJ_TYPES:
            have = live[kind].get(name)
            if have is None or digest(comparable(kind, have)) != dg:
                print(f"verify: DIFFERENT {key}: {'missing' if have is None else 'changed since import'}")
                bad += 1
            elif kind == "internalusers" and have.get("hash") != sec["internalusers"][name].get("hash"):
                print(f"verify: DIFFERENT {key}: hash is not the 4.x hash")
                bad += 1
            else:
                print(f"verify: ok {key}" + (" (same bcrypt hash as 4.x)" if kind == "internalusers" else ""))
    print(f"verify: {len(state)} item(s) written by the tool, {bad} different")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["export", "import", "verify"])
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--cacert", required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--resolve", action="append")
    ap.add_argument("--local", default="", help="prefix to run local commands on the 4.x indexer host (lab: 'docker exec CONTAINER')")
    ap.add_argument("--conf-dir", default="/etc/wazuh-indexer")
    ap.add_argument("--home", default="/usr/share/wazuh-indexer")
    ap.add_argument("--field-map", default="", help="M1 field map (C23); merged default: none, the corrected loader map's rules are used")
    ap.add_argument("--history-map", default=os.path.join(HERE, "history-loader-map.json"))
    ap.add_argument("--local5", default="", help="prefix to run local commands on a 5.0 indexer node (securityadmin fallback)")
    ap.add_argument("--certs-dir5", default="/etc/wazuh-indexer/certs", help="admin certificate directory on the 5.0 node")
    ap.add_argument("--securityadmin-host", default="localhost")
    ap.add_argument("--dashboard-public-url", default="", help="5.0 dashboard URL for SAML kibana_url, if it differs from 4.x")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--grant-states", action="store_true", help="also grant read on wazuh-states-* to roles that read alerts")
    a = ap.parse_args()
    sys.exit({"export": cmd_export, "import": cmd_import, "verify": cmd_verify}[a.cmd](a) or 0)


if __name__ == "__main__":
    main()
