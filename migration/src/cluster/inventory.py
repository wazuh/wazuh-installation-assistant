#!/usr/bin/env python3
"""inventory.py - the cluster inventory migrate-cluster.sh reads. Python 3.8+, standard library only.

The inventory is a JSON file the user writes once; nothing in it is a secret (the SSH key is named by its path):

  {
    "ssh": {"user": "wazuh-admin", "key": "/home/me/.ssh/wazuh-migration", "port": 22, "options": []},
    "work_dir": "/root/wazuh-migration",            the tool, the inputs and the assistants' scratch on every node
    "bundle_dir": "/root/wazuh-migration-bundle",   each node's bundle (outside every directory an installer deletes)
    "state_dir": "/root/wazuh-migration-cluster",   on this controller: markers, journal, results, logs, decisions
    "inputs": {                                     files on this controller, https:// URLs a node fetches itself, or
                                                    node:<node>:<path> (already on that node: streamed host to host,
                                                    never through a file on this controller; for the install files)
      "v4_install_files": "/root/wazuh-install-files.tar",   the 4.x assistant's install files (passwords, certificates)
      "v4_assistant": "https://packages.wazuh.com/4.14/wazuh-install.sh",
      "v5_assistant": "...wazuh-install.sh",        the 5.0 installation assistant
      "v5_artifact_urls": "",                       a development build's artifact_urls.yaml; empty for a release
      "v5_config": "/root/config.yml",              the 5.0 assistant's config.yml (every node, names and addresses)
      "identity_tool": "/root/wazuh-migrate-identity.py",
      "ruleset_tool": "/root/ruleset-migration"     a directory: rmig at 7976ef5422 or later (builds.json)
    },
    "nodes": [
      {"name": "node-1", "role": "indexer", "address": "10.0.0.11", "setup": true},
      {"name": "node-2", "role": "indexer", "address": "10.0.0.12"},
      {"name": "wazuh-1", "role": "master", "address": "10.0.0.21"},
      {"name": "wazuh-2", "role": "worker", "address": "10.0.0.22"},
      {"name": "dashboard", "role": "dashboard", "address": "10.0.0.31"}
    ],
    "settings": {"HISTORY_RETENTION": "", "UNCLASSIFIED_DECISION": "", "WPK_REPO": ""}
  }

"name" is the node's name in the 5.0 config.yml (the assistant's -wi/-wm/-wd argument; the manager's node_name).
"address" is where this controller reaches the node over SSH and where the other nodes reach its indexer or manager;
"ssh_address" overrides the first when the controller reaches it another way, and "ssh": {"user", "key", "port"} on a
node overrides the inventory's for that node. "setup": the indexer node that runs the
5.0 assistant's -g and -s and holds the indexer security bundle (default: the first indexer). "settings" takes the
names of migrate.sh's settings; an environment variable of the same name wins.

  inventory.py check <inventory>                 every problem on its own line; exit 1 when there is one
  inventory.py nodes <inventory> [role...]       "name role address ssh_address" lines, inventory order
  inventory.py get <inventory> <key[.key...]>    one value (empty when absent)
  inventory.py settings <inventory>              "NAME=value" lines of the settings object (shell-quoted)
"""
import json
import os
import re
import shlex
import stat
import sys

ROLES = ("indexer", "master", "worker", "dashboard")
DEFAULTS = {"work_dir": "/root/wazuh-migration", "bundle_dir": "/root/wazuh-migration-bundle"}
UNSAFE = ("/var/ossec", "/var/lib/wazuh-indexer", "/etc/wazuh-indexer", "/usr/share/wazuh-indexer", "/var/wazuh-manager",
          "/etc/wazuh-manager", "/etc/wazuh-dashboard", "/usr/share/wazuh-dashboard", "/var/lib/wazuh-dashboard",
          "/etc/filebeat", "/var/lib/filebeat", "/usr/share/filebeat", "/tmp", "/var/tmp", "/run", "/dev/shm")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SETTING = re.compile(r"^[A-Z][A-Z0-9_]*$")
REQUIRED_INPUTS = ("v4_install_files", "v4_assistant", "v5_assistant", "v5_config", "identity_tool", "ruleset_tool")


def load(path):
    with open(path) as f:
        inv = json.load(f)
    for k, v in DEFAULTS.items():
        inv.setdefault(k, v)
    inv.setdefault("state_dir", os.path.join(os.path.dirname(os.path.abspath(path)), "cluster-state"))
    inv.setdefault("inputs", {})
    inv.setdefault("settings", {})
    inv.setdefault("ssh", {})
    nodes = inv.get("nodes") or []
    idx = [n for n in nodes if n.get("role") == "indexer"]
    if idx and not any(n.get("setup") for n in idx):
        idx[0]["setup"] = True
    for n in nodes:
        n.setdefault("ssh_address", n.get("address"))
    return inv


def problems(inv, inv_path):
    p = []
    nodes = inv.get("nodes") or []
    if not nodes:
        p.append("no nodes")
    names = [n.get("name") for n in nodes]
    for n in nodes:
        if n.get("role") not in ROLES:
            p.append("node %s: role %r is not one of %s" % (n.get("name"), n.get("role"), ", ".join(ROLES)))
        if not NAME.match(str(n.get("name") or "")):
            p.append("node %r: the name must be the node's name in the 5.0 config.yml (letters, digits, . _ -)" % n.get("name"))
        if not n.get("address"):
            p.append("node %s: no address" % n.get("name"))
    dup = sorted({x for x in names if names.count(x) > 1})
    if dup:
        p.append("node names used twice: %s" % ", ".join(map(str, dup)))
    by = {r: [n for n in nodes if n.get("role") == r] for r in ROLES}
    if len(by["master"]) != 1:
        p.append("exactly one master is needed, the inventory has %d" % len(by["master"]))
    if not by["indexer"]:
        p.append("no indexer node")
    if len([n for n in by["indexer"] if n.get("setup")]) > 1:
        p.append("more than one indexer node is marked setup (the node that runs -g and -s)")
    if len(by["dashboard"]) > 1:
        p.append("more than one dashboard node: this version migrates one")
    for n in nodes:
        if n.get("setup") and n.get("role") != "indexer":
            p.append("node %s: only an indexer node can be the setup node" % n.get("name"))
    for n in nodes:
        ssh = dict(inv.get("ssh") or {}, **(n.get("ssh") or {}))
        who = "node %s: " % n.get("name") if n.get("ssh") else ""
        if not ssh.get("user"):
            p.append(who + "ssh.user is not set")
        key = ssh.get("key")
        if not key:
            p.append(who + "ssh.key is not set (the path of the private key this controller uses)")
        elif not os.path.isfile(key):
            p.append(who + "ssh.key %s does not exist on this controller" % key)
        elif os.stat(key).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            p.append(who + "ssh.key %s can be read by others than its owner (ssh refuses it)" % key)
    p = list(dict.fromkeys(p))
    for k in ("work_dir", "bundle_dir"):
        d = inv.get(k) or ""
        if not d.startswith("/"):
            p.append("%s must be an absolute path on the nodes: %r" % (k, d))
        else:
            hit = [u for u in UNSAFE if (os.path.normpath(d) + "/").startswith(u + "/")]
            if hit:
                p.append("%s %s is under %s, which a removal, an installer or a reboot deletes" % (k, d, hit[0]))
    if os.path.normpath(inv.get("work_dir", "")) == os.path.normpath(inv.get("bundle_dir", "")):
        p.append("work_dir and bundle_dir must differ (the finish deletes secrets from both, differently)")
    ins = inv.get("inputs") or {}
    for k in REQUIRED_INPUTS:
        v = ins.get(k)
        if not v:
            p.append("inputs.%s is not set" % k)
        elif v.startswith("node:"):
            parts = v.split(":", 2)
            if len(parts) != 3 or parts[1] not in names or not parts[2].startswith("/"):
                p.append("inputs.%s %s: the form is node:<node name>:<absolute path on that node>" % (k, v))
        elif not re.match(r"^https?://", v) and not os.path.exists(v):
            p.append("inputs.%s %s does not exist on this controller" % (k, v))
    v = ins.get("v5_artifact_urls")
    if v and not re.match(r"^https?://", v) and not os.path.exists(v):
        p.append("inputs.v5_artifact_urls %s does not exist on this controller" % v)
    if ins.get("ruleset_tool") and not re.match(r"^https?://", ins["ruleset_tool"]) and os.path.exists(ins["ruleset_tool"]) \
            and not os.path.isdir(ins["ruleset_tool"]):
        p.append("inputs.ruleset_tool must be a directory (wazuh/intelligence-data tools/ruleset-migration)")
    elif ins.get("ruleset_tool") and os.path.isdir(ins["ruleset_tool"]):
        # the rmig this tool was tested with (manifest/builds.json ruleset_tool, rmig commit 7976ef5422cdf677b702bf774645b0f6f4be9218):
        # an older one refuses --findings and never stops for the mandatory review
        for rel, token in (("rmig/reasons.py", "RM-P-REVIEW-PENDING"), ("rmig/cli.py", "--findings"), ("rmig/api/commands.py", "--engine-limit")):
            try:
                ok_ = token in open(os.path.join(ins["ruleset_tool"], rel), errors="replace").read()
            except OSError:
                ok_ = False
            if not ok_:
                p.append("inputs.ruleset_tool %s is older than the ruleset tool this tool was tested with (rmig 7976ef5422): it "
                         "lacks %s (%s)" % (ins["ruleset_tool"], token, rel))
    for k in (inv.get("settings") or {}):
        if not SETTING.match(k):
            p.append("settings.%s is not a setting name (migrate.sh's names, upper case)" % k)
    return p


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    cmd, path = argv[1], argv[2]
    try:
        inv = load(path)
    except (OSError, ValueError) as e:
        print("the inventory %s cannot be read: %s" % (path, e))
        return 1
    if cmd == "check":
        p = problems(inv, path)
        for x in p:
            print("inventory: " + x)
        return 1 if p else 0
    if cmd == "nodes":
        want = argv[3:]
        for n in inv.get("nodes") or []:
            if not want or n.get("role") in want or (("setup" in want) and n.get("setup")):
                s = dict(inv.get("ssh") or {}, **(n.get("ssh") or {}))
                print("%s %s %s %s %s %s %s" % (n["name"], n["role"], n["address"], n.get("ssh_address") or n["address"],
                                               s.get("user") or "-", s.get("key") or "-", s.get("port") or 22))
        return 0
    if cmd == "get":
        v = inv
        for k in argv[3].split("."):
            v = v.get(k) if isinstance(v, dict) else None
        if isinstance(v, (list, dict)):
            print(json.dumps(v))
        elif v is not None:
            print(v)
        return 0
    if cmd == "settings":
        for k, v in sorted((inv.get("settings") or {}).items()):
            if SETTING.match(k):
                print("%s=%s" % (k, shlex.quote(str(v))))
        return 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
