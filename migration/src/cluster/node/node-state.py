#!/usr/bin/env python3
"""node-state.py [--bundle DIR] : K5. Reads a manager node's REAL state (never the step markers) and prints it with the
decision a controller should take next. Run as root on the node. Standard library only.

What it reads: which manager package is installed (4.x / 5.0 / none) and whether an assistant or package transaction is
still running; the service; which agent and cluster ports listen and on which address; the host firewall guards present;
the registry on disk (client.keys) compared with the bundle's identity manifest by id, name AND key; the cluster peers;
Filebeat; and, for information only, the markers the node steps wrote.
"""
import json, os, re, subprocess, sys, hashlib

BUNDLE = "/root/wazuh-migration-bundle"
for i, a in enumerate(sys.argv):
    if a == "--bundle":
        BUNDLE = sys.argv[i + 1]


def sh(cmd, timeout=30):
    try:
        return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout).stdout.decode(errors="replace").strip()
    except Exception as e:  # noqa: BLE001
        return "ERROR %s" % e


DEB = os.path.exists("/usr/bin/dpkg-query") and os.path.exists("/usr/bin/apt-get")   # deb nodes too (F3 ran deb)


def rpmver(name):
    """The installed version of a package, from the package database (rpm or dpkg), or None."""
    if DEB:
        out = sh("dpkg-query -W -f='${db:Status-Status} ${Version}' %s 2>/dev/null" % name)
        return out.split()[1] if out.startswith("installed ") and len(out.split()) > 1 else None
    out = sh("rpm -q --qf '%%{VERSION}-%%{RELEASE}' %s" % name)
    return None if "not installed" in out or out.startswith("ERROR") else out


def keys(path):
    d = {}
    if not os.path.isfile(path):
        return None
    for line in open(path, errors="replace"):
        f = line.split()
        if len(f) >= 4 and not f[1].startswith("!") and not f[1].startswith("#"):
            d["%03d" % int(f[0])] = (f[1], f[3])
    return d


st = {}
st["pkg_4x"] = rpmver("wazuh-manager") if os.path.isdir("/var/ossec") else None
v = rpmver("wazuh-manager")
st["pkg_manager"] = v
st["generation"] = None if not v else ("5.0" if v.startswith("5.") else "4.x")
st["pkg_filebeat"] = rpmver("filebeat")
st["busy"] = [l for l in sh("pgrep -a -f 'wazuh-install.sh|rpm -i|rpm -e|yum |dnf |dpkg |apt-get ' | grep -v -E 'pgrep|node-state'").splitlines() if l.strip()]
st["service"] = sh("systemctl is-active wazuh-manager")
st["service_enabled"] = sh("systemctl is-enabled wazuh-manager")
st["filebeat"] = sh("systemctl is-active filebeat")
listen = sh("ss -ltnH").splitlines()
st["listen"] = sorted({l.split()[3] for l in listen if re.search(r":(1514|1515|1516|1517|55000)$", l.split()[3])})
# the shared guard uses its own chains (MIGGUARD = agent, MIGGUARD_CLUSTER = cluster) or nft table migguard;
# K5's and F4's comment-tagged INPUT rules are still recognised on a node set up by the arms
_ipt = sh("iptables -S INPUT; iptables -L INPUT -n")
st["guards"] = sorted(set(re.findall(r"/\* (k5-[a-z0-9-]+|f4-agent-guard) \*/", _ipt))
                      | ({"k5-agent-guard"} if re.search(r"-j MIGGUARD\b", _ipt) else set())
                      | ({"k5-cluster-guard"} if "-j MIGGUARD_CLUSTER" in _ipt else set())
                      | ({"k5-agent-guard"} if "chain agent" in sh("nft list table inet migguard 2>/dev/null") else set())
                      | ({"k5-cluster-guard"} if "chain cluster" in sh("nft list table inet migguard 2>/dev/null") else set()))
st["guard_rules"] = [l for l in sh("iptables -S INPUT").splitlines() if "guard" in l]

if st["generation"] == "4.x":
    kp = "/var/ossec/etc/client.keys"; cc = "/var/ossec/bin/cluster_control -l"
elif st["generation"] == "5.0":
    kp = "/etc/wazuh-manager/client.keys"; cc = "/var/wazuh-manager/bin/cluster_control -l"
else:
    kp = cc = None
reg = keys(kp) if kp else None
st["registry_on_disk"] = None if reg is None else {"entries": len(reg), "sha256": hashlib.sha256(open(kp, "rb").read()).hexdigest()[:16]}
st["cluster"] = sh(cc, timeout=40).splitlines()[-4:] if cc and st["service"] == "active" else []

man = os.path.join(BUNDLE, "identity", "manifest.json")
want = None
if os.path.isfile(man):
    m = json.load(open(man))
    want = {"%03d" % a["id"]: (a["name"], a["key"]) for a in m.get("agents", [])}
cmp = None
if want is not None and reg is not None:
    same = [i for i in want if i in reg and reg[i] == want[i]]
    missing = [i for i in want if i not in reg]
    wrong = [i for i in reg if i in want and reg[i] != want[i]]
    foreign = [i for i in reg if i not in want]
    cmp = {"bundle": len(want), "equal": len(same), "missing": missing, "different_key_or_name": wrong, "not_in_bundle": foreign}
st["registry_vs_bundle"] = cmp
st["markers"] = sorted(os.listdir(os.path.join(BUNDLE, "state"))) if os.path.isdir(os.path.join(BUNDLE, "state")) else []
st["bundle_manifest_ok"] = (sh("cd %s && grep -v -E '  \\./decisions\\.json$' MANIFEST.sha256 | sha256sum --quiet -c - >/dev/null 2>&1 && echo yes || echo no" % BUNDLE) if os.path.isfile(os.path.join(BUNDLE, "MANIFEST.sha256")) else "no manifest")

# --- the decision, from the real state only
agent_ports_open = any(re.search(r"(0\.0\.0\.0|\*|\[::\]):(1514|1515|1517)$", l) for l in st["listen"])
agent_guard = any(g in ("k5-agent-guard", "f4-agent-guard") for g in st["guards"])
cluster_guard = "k5-cluster-guard" in st["guards"]
if st["busy"]:
    d = "WAIT: an assistant or a package transaction is still running on this node"
elif st["generation"] is None:
    d = "NO MANAGER: 4.x removed and nothing installed (or a rolled-back install); next: install (forward) or reinstall 4.x (back)"
elif cmp is None:
    d = "NO BUNDLE TO COMPARE: refuse to decide"
elif st["generation"] == "4.x":
    if cmp["equal"] == cmp["bundle"] and not cmp["different_key_or_name"] and not cmp["not_in_bundle"]:
        d = "4.x RESTORED: registry equals the bundle (id, name, key); next: open the cluster port, check the workers, then lift the agent guard"
    else:
        d = "4.x REINSTALLED, NOT RESTORED (registry %d of %d, foreign %s): keep every guard (agent AND cluster port), restore from the bundle" % (
            cmp["equal"], cmp["bundle"], cmp["not_in_bundle"])
else:  # 5.0
    if st["service"] != "active":
        d = "5.0 INSTALLED, SERVICE %s: repair the install before anything else" % st["service"]
    elif cmp["equal"] == 0 and not cmp["not_in_bundle"]:
        d = "5.0 READY, IMPORT NOT STARTED: run the import"
    elif cmp["different_key_or_name"] or cmp["not_in_bundle"]:
        d = "5.0 REGISTRY DIFFERS FROM THE BUNDLE (%s, foreign %s): STOP" % (cmp["different_key_or_name"], cmp["not_in_bundle"])
    elif cmp["missing"]:
        d = "IMPORT CUT: %d of %d in, every one equal; insert the missing %s from the bundle, then restart, resets, compare-and-repair" % (cmp["equal"], cmp["bundle"], cmp["missing"])
    else:
        d = "IMPORT COMPLETE ON DISK (every agent equal to the bundle); next: clean restart, password resets, compare-and-repair memberships, check"
st["agent_ports_open_to_all"] = agent_ports_open
st["decision"] = d
print(json.dumps(st, indent=1))
print("DECISION:", d)
