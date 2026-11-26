#!/usr/bin/env python3
"""next_flow.py - the one-command flow's helpers (migrate.sh with no command, or `migrate.sh next`). Python 3.8+,
standard library only.

Every question the migration asks a person lives in a decisions file (JSON). This module finds the next open one and
prints it, asks the flow's own questions (the inputs it cannot find, the point of no return, the role loss, SSH access
for a cluster) and reads their answers, and builds a cluster inventory from the 4.x master.

  next_flow.py question FILE...                   print the first open question (exit 0), or nothing (exit 1)
  next_flow.py open FILE...                       exit 0 when any question is open, else 1 (prints nothing)
  next_flow.py answer FILE SECTION ID             print the answer ("action") of a flow question; exit 1 when open
  next_flow.py ask FILE SECTION ID JSON           write a flow question (kept as is when it is already answered)
  next_flow.py no-return FILE COMMAND KIND        the point-of-no-return question (KIND: all-in-one or cluster)
  next_flow.py role-loss FILE AUDIT-JSON          the role-loss question of the history (rule 9)
  next_flow.py carry-answers OLD NEW              a new attempt after going back keeps the earlier answers
  next_flow.py attempt-answers FILE STAMP|-       set aside the point-of-no-return and finish answers of another attempt
  next_flow.py inputs FILE NAME=PATH|-...         for each input: the given or found path, else the answered one, else
                                                  a question; prints NAME=value lines (shell-quoted); exit 3 if one is open
  next_flow.py last-failure RESULTS-DIR           "<description>\\t<log>" of the newest failed step result
  next_flow.py cluster-role OSSEC-CONF            single, master, or "worker <master address>"
  next_flow.py v5-config-check CONFIG.YML INVENTORY  the 5.0 config.yml against the inventory, before anything is removed
  next_flow.py cluster-inventory OUT --install-files TAR [--inputs JSON] [--api URL]
                                                  write the inventory (managers from the cluster API, indexer and
                                                  dashboard nodes from the install files' config.yml) and the 5.0
                                                  config.yml beside it; SSH access is left for the ssh question
  next_flow.py ssh INVENTORY FILE                 fill the inventory's SSH user and key from the answer (exit 0), or
                                                  ask for them (exit 3)
"""
import glob
import json
import os
import re
import shlex
import ssl
import sys
import tarfile
import time
import urllib.request
import base64

FLOW_SECTIONS = ("inputs", "ssh-access", "point-of-no-return", "history-roles", "unclassified-finish")
SETTINGS_ANSWERS = ("keep", "replace", "omit")


# ------------------------------------------------------------------------------------------------ the decisions file
def load(path):
    try:
        with open(path) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save(path, d):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=1, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def flow_entries(d, section):
    sec = d.get(section)
    return sec if isinstance(sec, list) else []


def flow_entry(d, section, ident):
    return next((e for e in flow_entries(d, section) if isinstance(e, dict) and e.get("id") == ident), None)


def flow_open(e):
    """A flow question is open while its answer is missing: "action" null, or a required field still null."""
    if not isinstance(e, dict):
        return False
    need = e.get("fill") or []
    if need:
        return any(e.get(k) in (None, "") for k in need)
    return e.get("action") in (None, "")


def open_questions(d):
    """(section, id, text, how to answer) of every open question of one decisions file, in the order the flow asks."""
    out = []
    for sec in ("inputs", "ssh-access"):
        for e in flow_entries(d, sec):
            if flow_open(e):
                out.append((sec, e.get("id"), e.get("question", ""), e.get("answer", "")))
    for sec in ("settings", "groups-pre-upgrade", "groups-post-upgrade"):
        s = d.get(sec) or {}
        if not isinstance(s, dict):
            continue
        items = [(None, i, e) for i, e in sorted(s.items())] if sec == "settings" else \
            [(g, i, e) for g, ent in sorted(s.items()) if isinstance(ent, dict) for i, e in sorted(ent.items())]
        for g, i, e in items:
            if isinstance(e, dict) and e.get("action") not in SETTINGS_ANSWERS:
                q = e.get("question") or {}
                text = q.get("asks") if isinstance(q, dict) else str(q)
                where = ("group %s, " % g) if g else ""
                opt = q.get("option") if isinstance(q, dict) else None
                ans = q.get("answers") if isinstance(q, dict) else None
                allowed = q.get("allowed") if isinstance(q, dict) else None
                how = "set \"action\" to %s" % (" or ".join('"%s"' % k for k in (ans or {"keep": 1, "replace": 1, "omit": 1})))
                if allowed:
                    how += " (%s)" % allowed
                if ans and "replace" in ans:
                    how += "; \"replace\" takes the new value in \"value\" (a number can be written 10 or \"10\")"
                how += ", and a few words in \"reason\" (every answer needs one; it is kept in the settings report)"
                out.append((sec, (g + "/" if g else "") + i, "%s%s: %s" % (where, opt or i, text or "see the converter's report"), how))
    rs = d.get("ruleset")
    if isinstance(rs, dict) and rs:
        for name, e in sorted((rs.get("fields") or {}).items()):
            if isinstance(e, dict) and e.get("action") is None and e.get("required", True) is not False:
                out.append(("ruleset", "fields/" + name, "the 4.x field %s (used by %s) has no 5.0 field" % (name, ", ".join(e.get("used_by") or [])),
                            "set \"action\" to \"map\" with the 5.0 field in \"wcs\", or to \"drop\""))
        hints = d.get("ruleset-hints") if isinstance(d.get("ruleset-hints"), dict) else {}
        for key, e in sorted((rs.get("stock") or {}).items()):
            if isinstance(e, dict) and (not e.get("integration") or (not key.startswith("decoder:") and not e.get("selection"))):
                h = hints.get("stock/" + key) or {}
                text = "the stock 4.x %s is used by custom content (%s): name the 5.0 integration that receives its events" % (key, ", ".join(e.get("used_by") or []))
                if h.get("decoders_4x") or h.get("groups_4x"):
                    text += " (on 4.x: decoder %s, groups %s)" % (", ".join(h.get("decoders_4x") or []) or "none", ", ".join(h.get("groups_4x") or []) or "none")
                if h.get("candidates"):
                    text += "; 5.0 integrations whose names match, to check: %s" % ", ".join(h["candidates"])
                how = "fill \"integration\" with a 5.0 integration name"
                if not key.startswith("decoder:"):
                    how += (" and \"selection\" with the 5.0 fields and values that pick this rule's events, as an object "
                            "(for example {\"process.name\": \"sshd\", \"event.outcome\": \"failure\"})")
                    if h.get("fields_file"):
                        how += "; the 5.0 field names are listed in %s" % h["fields_file"]
                out.append(("ruleset", "stock/" + key, text, how))
        for rid, e in sorted((rs.get("feeds") or {}).items()):
            if isinstance(e, dict) and e.get("selector_needed") and not e.get("selector"):
                out.append(("ruleset", "feeds/" + rid, "the root rule %s needs a decoder check that selects its events" % rid,
                            "write the check in \"selector\""))
        for rid, e in sorted((rs.get("findings") or {}).items()):
            if isinstance(e, dict) and e.get("action") is None and not e.get("mitre"):
                out.append(("ruleset", "findings/" + rid, "the 4.x rule %s has no MITRE technique but looks like a security finding (%s)" % (rid, e.get("why", "")),
                            "add techniques in \"mitre\", or set \"action\" to \"finding\" or \"telemetry\""))
        if rs.get("review") != "accepted":
            out.append(("ruleset", "review", "read the ruleset tool's review (the block \"Review before activate\" of its report.md, "
                        "printed above in the run's output and kept in the bundle's ruleset-migration/report.md)",
                        "set \"review\" to \"accepted\""))
    for sec in ("unclassified-decision", "history-roles", "point-of-no-return", "unclassified-finish"):
        for e in flow_entries(d, sec):
            if flow_open(e):
                ch = e.get("choices") or []
                out.append((sec, e.get("id"), e.get("question", ""), e.get("answer") or ("set \"action\" to %s" % " or ".join('"%s"' % c for c in ch))))
    # a cluster: every node's questions in the controller's one file, under "nodes" -> "<node>"
    nodes = d.get("nodes") if isinstance(d.get("nodes"), dict) else {}
    for node, nd in sorted(nodes.items()):
        if isinstance(nd, dict):
            for sec, ident, text, how in open_questions(nd):
                out.append(("nodes\", \"%s\", \"%s" % (node, sec), ident, "node %s: %s" % (node, text), how))
    return out


def files_of(args):
    out = []
    for a in args:
        out += sorted(glob.glob(a)) if any(c in a for c in "*?[") else [a]
    return [f for f in out if os.path.isfile(f)]


def cmd_question(*files):
    """The first open question in full, then every other open question of every file given, each with what its answer
    needs (and its file when it is another one): one stop shows all that the person answers before running again."""
    allq = [(f, q) for f in files_of(files) for q in open_questions(load(f))]
    if not allq:
        return 1
    f, (sec, ident, text, how) = allq[0]
    print("QUESTION: %s" % text)
    print("  answer in: %s" % f)
    print("  entry:     section \"%s\", \"%s\"" % (sec, ident))
    print("  how:       %s" % how)
    if len(allq) > 1:
        print("  %d more question(s) are open; answer them all before running again:" % (len(allq) - 1))
        for f2, (sec2, ident2, text2, how2) in allq[1:30]:
            print("  - section \"%s\", \"%s\"%s: %s" % (sec2, ident2, "" if f2 == f else " (in %s)" % f2, text2))
            print("      how: %s" % how2)
        if len(allq) > 30:
            print("  - and %d more: every entry with \"action\": null (or an empty field) in the files above" % (len(allq) - 30))
    return 0


def cmd_open(*files):
    return 0 if any(open_questions(load(f)) for f in files_of(files)) else 1


def cmd_answer(path, section, ident):
    e = flow_entry(load(path), section, ident)
    if e is None or flow_open(e):
        return 1
    print(e.get("action") if not e.get("fill") else json.dumps({k: e.get(k) for k in e["fill"]}))
    return 0


def ask(path, section, entry):
    d = load(path)
    old = flow_entry(d, section, entry["id"])
    if old is not None and not flow_open(old):
        return False
    if old is not None:
        for k in (entry.get("fill") or []) + ["action"]:
            if old.get(k) not in (None, ""):
                entry[k] = old[k]
    entry.setdefault("asked", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    d[section] = [e for e in flow_entries(d, section) if not (isinstance(e, dict) and e.get("id") == entry["id"])] + [entry]
    save(path, d)
    return True


def cmd_ask(path, section, ident, js):
    e = json.loads(js)
    e["id"] = ident
    ask(path, section, e)
    return 0


AFTER_OUTAGE = ("point-of-no-return", "unclassified-finish", "unclassified-decision")


def cmd_attempt_answers(path, stamp):
    """attempt-answers FILE STAMP: the answers that belong to one attempt's outage are never read by another attempt.
    STAMP "-" (this attempt has not frozen 4.x yet): every point-of-no-return and finish answer in the file is from an
    earlier attempt; set aside under "earlier-attempts" (kept, never read). Otherwise STAMP names this attempt (its state
    directory and the mark written there once): a point-of-no-return entry written for another one is set aside, so a
    "confirm" given to an earlier attempt can never skip this attempt's stop."""
    d = load(path)
    if not d:
        return 0
    moved = []

    def take(holder, sec, where):
        v = holder.pop(sec, None)
        if v:
            moved.append({"section": sec, "where": where, "entries": v,
                          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})

    if stamp == "-":
        for sec in AFTER_OUTAGE:
            take(d, sec, "")
            for node, nd in (d.get("nodes") or {}).items():
                if isinstance(nd, dict):
                    take(nd, sec, node)
    else:
        e = flow_entry(d, "point-of-no-return", "confirm-no-return")
        if e is not None and e.get("attempt") != stamp:
            take(d, "point-of-no-return", "")
    if not moved:
        return 0
    d.setdefault("earlier-attempts", []).extend(moved)
    save(path, d)
    print("answers of an earlier attempt set aside in %s (section \"earlier-attempts\"; never read): %s. The point of no "
          "return is asked again after this attempt's outage." % (path, ", ".join(sorted({m["section"] for m in moved}))))
    return 0


def cmd_no_return(path, command, kind, stamp=""):
    back = "%s back" % command
    ask(path, "point-of-no-return", {
        "id": "confirm-no-return", "action": None, "choices": ["confirm"], "attempt": stamp or None,
        "question": "POINT OF NO RETURN. 5.0 now serves the agents of this %s as 4.x agents, and the old alerts are loaded. "
                    "Until you confirm, '%s' returns to 4.14.x from the bundle. After the confirmation the agents are upgraded "
                    "to 5.0 and going back is refused: an upgraded agent cannot return to a 4.x manager. Answer \"confirm\" "
                    "to upgrade the agents and finish." % ("cluster" if kind == "cluster" else "host", back)})
    return 0


def cmd_carry_answers(old, new):
    """carry-answers OLD NEW: a new attempt after going back keeps the person's answers (inputs, SSH access, settings,
    groups, ruleset, role loss) from the attempt that went back; only the point of no return and the finish's raw
    question are asked again. An answer already in NEW is kept."""
    o, n = load(old), load(new)
    for k, v in o.items():
        if k in AFTER_OUTAGE or k in ("earlier-attempts",) or k in n:
            continue
        n[k] = v
    if n:
        save(new, n)
    print("answers carried from %s: %s" % (old, ", ".join(sorted(k for k in n if k in o)) or "none"))
    return 0


def cmd_role_loss(path, audit):
    roles = []
    try:
        a = json.load(open(audit))
        roles = sorted(a.get("lose_modules") or [])
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    ask(path, "history-roles", {
        "id": "role-loss", "action": None, "choices": ["accept"],
        "question": "These indexer roles name finding streams exactly, so they lose every module when the old alerts are "
                    "switched on: %s (the whole audit: %s). Fix the roles on the 5.0 indexer and run again, or answer "
                    "\"accept\" to switch the old alerts on anyway." % (", ".join(map(str, roles[:20])) or "see the audit", audit),
        "roles": roles[:100]})
    return 0


# ------------------------------------------------------------------------------------------------ inputs
INPUTS = {
    "V4_INSTALL_FILES_TAR": ("file", "wazuh-install-files.tar, the file the 4.x installation assistant wrote (passwords and certificates)",
                             ["wazuh-install-files.tar"]),
    "IDENTITY_TOOL": ("file", "wazuh-migrate-identity.py, the identity tool of wazuh/wazuh 5.0 (tools/migration)",
                      ["wazuh-migrate-identity.py", "mig-tools/wazuh-migrate-identity.py"]),
    "RMIG_DIR": ("dir", "the ruleset migration tool directory (tools/ruleset-migration of the ruleset repository, with its rmig/ folder)",
                 ["ruleset-migration", "mig-tools/ruleset-migration"]),
}


def found(kind, p):
    if not p:
        return False
    if kind == "dir":
        return os.path.isdir(os.path.join(p, "rmig"))
    return os.path.isfile(p)


def cmd_inputs(path, *pairs):
    """NAME=given (the environment's value or the default) per input; a NAME given as NAME! was set explicitly and is
    used as it is. Search order: the given path, the answer in the decisions file, the usual places (the current
    directory, /root, the directory the one-file tool was started from)."""
    d = load(path)
    roots = [os.getcwd(), "/root", os.environ.get("WM_ORIGIN_DIR", "")]
    out, rc = [], 0
    for p in pairs:
        name, _, given = p.partition("=")
        explicit = name.endswith("!")
        name = name.rstrip("!")
        kind, what, names = INPUTS[name]
        if explicit:
            out.append((name, given))
            continue
        e = flow_entry(d, "inputs", name)
        val = None
        if found(kind, given):
            val = given
        elif e is not None and not flow_open(e) and found(kind, e.get("path")):
            val = e["path"]
        else:
            for r in roots:
                for n in names:
                    c = os.path.join(r, n) if r else ""
                    if found(kind, c):
                        val = c
                        break
                if val:
                    break
        if val:
            out.append((name, val))
            continue
        bad = e.get("path") if e and e.get("path") else None
        ask(path, "inputs", {"id": name, "fill": ["path"], "path": None,
                             "question": "Where is %s? It was not found at %s nor in the current directory or /root%s." % (
                                 what, given or "its default place", (" (the path answered, %s, does not hold it)" % bad) if bad else ""),
                             "answer": "write the absolute path in \"path\""})
        rc = 3
    for name, val in out:
        print("%s=%s" % (name, shlex.quote(val)))
    return rc


# ------------------------------------------------------------------------------------------------ failures
def cmd_last_failure(results):
    best = None
    for f in glob.glob(os.path.join(results, "*.json")):
        try:
            r = json.load(open(f))
        except (OSError, ValueError):
            continue
        if r.get("result") == "failed" and (best is None or os.path.getmtime(f) > best[0]):
            best = (os.path.getmtime(f), r, f[:-5] + ".log")
    if not best:
        return 1
    why = ""
    try:      # the step's own shell names the command that errexit stopped on (migrate.sh STEP_ERR_TRAP)
        stops = [l.split("STEP STOPPED: ", 1)[1].strip() for l in open(best[2], errors="replace") if "STEP STOPPED: " in l]
        why = ("; it stopped at: %s" % stops[-1]) if stops else ""
    except OSError:
        pass
    print("%s (step %s, exit %s)%s\t%s" % (best[1].get("description"), best[1].get("step"), best[1].get("exit"), why, best[2]))
    return 0


# ------------------------------------------------------------------------------------------------ clusters
def cluster_conf(text):
    """(disabled, node_type, master address) of the <cluster> block of an ossec.conf."""
    m = re.search(r"<cluster>(.*?)</cluster>", re.sub(r"<!--.*?-->", "", text, flags=re.S), re.S)
    if not m:
        return True, None, None
    b = re.sub(r"<!--.*?-->", "", m.group(1), flags=re.S)
    get = lambda t: (re.search(r"<%s>\s*([^<]*?)\s*</%s>" % (t, t), b) or [None, None])[1]
    nodes = re.findall(r"<node>\s*([^<]*?)\s*</node>", b)
    return (get("disabled") or "yes") != "no", get("node_type"), (nodes[0] if nodes else None)


def cmd_cluster_role(path):
    try:
        text = open(path, errors="replace").read()
    except OSError:
        print("single")
        return 0
    disabled, kind, master = cluster_conf(text)
    if disabled:
        print("single")
    elif kind == "worker":
        print("worker %s" % (master or "?"))
    else:
        print("master")
    return 0


def parse_config_yml(text):
    """The nodes of the assistant's config.yml: {"indexer": [{"name", "ip", ...}], "server"/"manager": [...],
    "dashboard": [...]}. Only the shape the assistants write: two-space indents, "- name:" items, scalar or list values."""
    nodes, role, item, key = {}, None, None, None
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip())
        s = line.strip()
        if ind == 2 and s.endswith(":"):
            role = s[:-1]
            nodes[role] = []
            item = key = None
        elif role and s.startswith("- ") and ind <= 6 and ":" in s:
            item = {}
            nodes[role].append(item)
            k, _, v = s[2:].partition(":")
            key = k.strip()
            item[key] = v.strip().strip("'\"") or []
        elif role and item is not None and s.startswith("- "):
            if isinstance(item.get(key), list):
                item[key].append(s[2:].strip().strip("'\""))
        elif role and item is not None and ":" in s:
            k, _, v = s.partition(":")
            key = k.strip()
            item[key] = v.strip().strip("'\"") or []
    for r in nodes.values():
        for n in r:
            for k, v in list(n.items()):
                if isinstance(v, list):
                    n[k] = v[0] if v else ""
    return nodes


def install_files(tar):
    """config.yml and the API user's password from wazuh-install-files.tar (never printed)."""
    conf, pw = None, {}
    with tarfile.open(tar) as t:
        for m in t.getmembers():
            base = os.path.basename(m.name)
            if base == "config.yml" and m.isfile():
                conf = t.extractfile(m).read().decode(errors="replace")
            elif base == "wazuh-passwords.txt" and m.isfile():
                txt = t.extractfile(m).read().decode(errors="replace")
                for k, u, p in re.findall(r"(\w+)_username:\s*'([^']*)'\s*\n\s*\w*_password:\s*'([^']*)'", txt):
                    pw.setdefault((k, u), p)
    return conf, pw


def api_nodes(url, user, password):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # the 4.x API's own certificate on this host, as every other call of the tool
    req = urllib.request.Request(url + "/security/user/authenticate?raw=true", method="POST",
                                 headers={"Authorization": "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()})
    tok = urllib.request.urlopen(req, context=ctx, timeout=30).read().decode().strip()
    req = urllib.request.Request(url + "/cluster/nodes?limit=1000", headers={"Authorization": "Bearer " + tok})
    d = json.loads(urllib.request.urlopen(req, context=ctx, timeout=30).read().decode())
    return [{"name": x["name"], "role": "master" if x.get("type") == "master" else "worker", "address": x.get("ip")}
            for x in d["data"]["affected_items"]]


def build_inventory(conf_text, managers, inputs):
    nodes = parse_config_yml(conf_text or "")
    if not managers:
        managers = [{"name": n["name"], "role": "master" if n.get("node_type") == "master" else "worker", "address": n.get("ip")}
                    for n in nodes.get("server") or nodes.get("manager") or []]
    managers = sorted(managers, key=lambda n: (n["role"] != "master", n["name"]))
    inv = {"ssh": {"user": None, "key": None},
           "inputs": inputs,
           "nodes": [{"name": n["name"], "role": "indexer", "address": n.get("ip")} for n in nodes.get("indexer") or []]
                    + managers
                    + [{"name": n["name"], "role": "dashboard", "address": n.get("ip")} for n in (nodes.get("dashboard") or [])[:1]],
           "settings": {},
           "built_by": "wazuh-migrate on the 4.x master (managers from the cluster API, indexer and dashboard nodes from the install files' config.yml)"}
    return inv


def config5(inv):
    """The 5.0 assistant's config.yml: the same nodes, the managers under "manager" (4.x calls them "server")."""
    out = ["nodes:"]
    for role, key in (("indexer", "indexer"), (None, "manager"), ("dashboard", "dashboard")):
        ns = [n for n in inv["nodes"] if (n["role"] == role if role else n["role"] in ("master", "worker"))]
        if not ns:
            continue
        out.append("  %s:" % key)
        for n in ns:
            out.append("    - name: %s" % n["name"])
            out.append('      ip: "%s"' % n["address"])
            if not role:
                out.append("      node_type: %s" % n["role"])
    return "\n".join(out) + "\n"


def cmd_cluster_inventory(out, *args):
    a = dict(zip(args[0::2], args[1::2]))
    tar = a.get("--install-files")
    inputs = json.loads(a.get("--inputs") or "{}")
    conf, pw = install_files(tar)
    if not conf:
        print("the install files %s hold no config.yml: write the inventory yourself (cluster/inventory.py says its format) "
              "and run again with --inventory FILE" % tar)
        return 1
    managers, note = [], ""
    try:
        managers = api_nodes(a.get("--api", "https://localhost:55000"), "wazuh", pw.get(("api", "wazuh"), ""))
        note = "managers from the cluster API"
    except Exception as e:   # the API is down: the config.yml's own list
        note = "managers from config.yml (the cluster API did not answer: %s)" % type(e).__name__
    inputs.setdefault("v4_install_files", tar)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    inv = build_inventory(conf, managers, inputs)
    v5 = os.path.join(os.path.dirname(os.path.abspath(out)), "config-5.0.yml")
    with open(v5, "w") as f:
        f.write(config5(inv))
    inv["inputs"].setdefault("v5_config", v5)
    save(out, inv)
    print("inventory written to %s: %s; indexer and dashboard nodes from the install files' config.yml" % (out, note))
    for n in inv["nodes"]:
        print("  %-10s %-24s %s" % (n["role"], n["name"], n["address"]))
    print("the 5.0 config.yml for the assistant: %s" % v5)
    return 0


def cmd_ssh(inventory, path):
    inv = load(inventory)
    ssh = inv.get("ssh") or {}
    if ssh.get("user") and ssh.get("key"):
        return 0
    e = flow_entry(load(path), "ssh-access", "ssh")
    if e is not None and not flow_open(e):
        inv["ssh"] = dict(ssh, user=e["user"], key=e["key"], port=int(e.get("port") or 22))
        save(inventory, inv)
        print("SSH access from the answer in %s: user %s, key %s (written into %s)" % (path, e["user"], e["key"], inventory))
        return 0
    names = ", ".join("%s (%s)" % (n["name"], n["address"]) for n in inv.get("nodes") or [])
    ask(path, "ssh-access", {"id": "ssh", "fill": ["user", "key"], "user": None, "key": None, "port": 22,
                             "question": "Which SSH user and private key does this host use to reach every node of the cluster, "
                                         "itself included? Nodes: %s. The user is root, or has sudo without a password." % names,
                             "answer": "write the user in \"user\" and the private key's absolute path on this host in \"key\" (\"port\" if not 22)"})
    return 3


def v5_config_problems(conf_text, inv_nodes):
    """(refusals, warnings) of the 5.0 config.yml against the inventory's nodes. The 5.0 assistant's -g reads it after
    the 4.x indexers and the dashboard are removed: a typo it refuses there leaves the cluster with no indexer, so what
    can be checked without the assistant is checked before anything is removed."""
    import ipaddress
    nodes, bad, warn = parse_config_yml(conf_text), [], []
    if not any(nodes.get(r) for r in ("indexer", "manager", "server", "dashboard")):
        return ["the 5.0 config.yml has no nodes (it needs nodes: indexer, manager, dashboard)"], []
    seen = {}
    for role in ("indexer", "manager", "server", "dashboard"):
        for n in nodes.get(role) or []:
            name, ip = str(n.get("name") or ""), str(n.get("ip") or "")
            if not name:
                bad.append("a %s node of the 5.0 config.yml has no name" % role)
                continue
            if (role, name) in seen:
                bad.append("%s node %s is named twice in the 5.0 config.yml" % (role, name))
            seen[(role, name)] = ip
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                if not ip or re.match(r"^[0-9.]+$", ip) or ":" in ip:
                    bad.append("%s node %s: %r is not a valid IP address (the 5.0 assistant's -g refuses it)" % (role, name, ip))
    want = {"indexer": ("indexer",), "master": ("manager", "server"), "worker": ("manager", "server"), "dashboard": ("dashboard",)}
    for n in inv_nodes:
        roles = want.get(n.get("role"))
        if not roles:
            continue
        hit = [seen[(r, n["name"])] for r in roles if (r, n["name"]) in seen]
        if not hit:
            bad.append("node %s (%s in the inventory) is not in the 5.0 config.yml under %s" % (n["name"], n["role"], " or ".join(roles)))
        elif n.get("address") and hit[0] != n["address"]:
            warn.append("node %s: the 5.0 config.yml says %s, the inventory %s (the certificates are made for the config.yml's)" % (n["name"], hit[0], n["address"]))
    return bad, warn


def cmd_v5_config_check(conf, inventory):
    """v5-config-check CONFIG.YML INVENTORY: exit 1 with a line per refusal; warnings are printed and pass."""
    inv = json.load(open(inventory))
    bad, warn = v5_config_problems(open(conf, errors="replace").read(), inv.get("nodes") or [])
    for w in warn:
        print("WARNING: %s" % w)
    for b in bad:
        print("REFUSED: %s" % b)
    return 1 if bad else 0


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    fn = {"question": cmd_question, "open": cmd_open, "answer": cmd_answer, "ask": cmd_ask, "no-return": cmd_no_return,
          "role-loss": cmd_role_loss, "inputs": cmd_inputs, "carry-answers": cmd_carry_answers, "attempt-answers": cmd_attempt_answers, "last-failure": cmd_last_failure, "cluster-role": cmd_cluster_role,
          "cluster-inventory": cmd_cluster_inventory, "ssh": cmd_ssh, "v5-config-check": cmd_v5_config_check}.get(argv[1])
    if not fn:
        sys.exit(__doc__)
    return fn(*argv[2:]) or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
