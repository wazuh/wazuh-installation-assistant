"""F7 fold: the user session counted on a fake host. The target for the user flow: a clean all-in-one reaches
MIGRATION FINISHED in 3 commands and 2 answer rounds; a cluster from its master in 4 commands and 3 rounds. The steps
behind the one command are stand-ins (a walker script), but every question is written by the tool's own code (the
settings converter's plan on E7's settings, the ruleset hints, the point of no return, the raw-at-finish question, the
SSH question, the cluster's carry of every node question into one file), and the person answers only what the printed
questions say: a field the "how" line does not name is not filled. E7-aio took 6 commands and 5 rounds, E8-cluster-deb
6 and 5."""
import json
import os
import re
import shutil
import tempfile
import unittest

import helpers
import test_f7_fold as F7

SRC = F7.SRC
NF = F7.NF
TOC = F7.TOC

WALKER = r'''
import json, os, subprocess, sys
sys.dont_write_bytecode = True
SRC, FX, STOCK, BASE, RULES, RMIG, ALL_RUN = sys.argv[1:8]
what, dec, state = sys.argv[8:11]
cdec, node = (sys.argv[11], sys.argv[12]) if len(sys.argv) > 12 else (None, None)
import importlib.util
def mod(name):
    s = importlib.util.spec_from_file_location(name + "_walk", os.path.join(SRC, name + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
H = mod("mig_helper")
def stamp(*ms):
    os.makedirs(state, exist_ok=True)
    for m in ms:
        open(os.path.join(state, m), "w").write("t\n")
def load(p):
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return {}
def settings(nodefile, work):
    # the real settings plan, against the E1 fixture (monitord.day_wait out of range, the syslog_output section removed)
    return subprocess.run([sys.executable, os.path.join(SRC, "settings_stage.py"), "plan", "--v4", os.path.join(FX, "e1x-aio"),
                           "--stock", STOCK, "--base", BASE, "--decisions", nodefile, "--work", work, "--groups", os.path.join(FX, "groups")],
                          stdout=sys.stdout, stderr=subprocess.STDOUT).returncode
def ruleset(flow):
    # what the ruleset step leaves in the flow file: E7's two stock questions and the review (rmig itself is not run)
    d = load(flow)
    if "ruleset" not in d:
        d["ruleset"] = {"version": 1, "review": None, "stock": {
            "rule:5716": {"integration": None, "selection": None, "used_by": ["rule:100300"]},
            "rule:80700": {"integration": None, "selection": None, "used_by": ["rule:100500"]}}}
        json.dump(d, open(flow, "w"))
    H.ruleset_hints(flow, RULES, RMIG)
    r = load(flow)["ruleset"]
    return 0 if r.get("review") == "accepted" and all(e.get("integration") and e.get("selection") for e in r["stock"].values()) else 3
def nodefile():
    f = os.path.join(os.path.dirname(state), "decisions", node + ".json")
    os.makedirs(os.path.dirname(f), exist_ok=True)
    H.node_carry("to-node", cdec, node, f, f)
    return f
if what == "precopy":
    work = os.path.join(os.path.dirname(state), "work")
    if cdec:
        f = nodefile(); rs = settings(f, work); H.node_carry("from-node", cdec, node, f); rr = ruleset(cdec)
    else:
        rs = settings(dec, work); rr = ruleset(dec)
    if rs == 0 and rr == 0:
        stamp("phase.assess", "phase.precopy"); sys.exit(0)
    sys.exit(3)
if what == "run":
    if not os.path.exists(os.path.join(state, "phase.precopy")):
        sys.exit(1)
    stamp(*ALL_RUN.split())
    open(os.path.join(state, "unclassified.applied"), "w").write("verified-none\nraw\n")     # E7: one rule not reproduced
    open(os.path.join(state, "ruleset.verify_summary"), "w").write("verify: REPRODUCED 4, NOT_REPRODUCED 1, NOT_SILENCED 0, NO_SAMPLE 1")
    sys.exit(0)
if what in ("finish", "raw-ask"):
    f = nodefile() if cdec else dec
    rc = H.raw_decision(f, state, "", "")
    if cdec:
        H.node_carry("from-node", cdec, node, f)
    if rc == 3:
        sys.exit(3)
    if what == "finish":
        stamp("phase.finish")
    sys.exit(0)
'''


def person(files, out):
    """Answers every open question of the decisions files with only what the printed QUESTION lines say. Returns the
    number of entries answered."""
    n = 0
    for f in files:
        d = json.load(open(f))
        for sec, ident, text, how in NF.open_questions(d):
            assert '"%s"' % ident in out, (ident, out[-3000:])          # printed in this stop
            path = [x.strip('"') for x in sec.split('", "')]
            tgt = d
            for p in path:
                tgt = tgt[p]
            if path[-1] in ("settings", "groups-pre-upgrade", "groups-post-upgrade"):
                e = tgt[ident]
                if '"keep"' not in how and '"omit"' in how:
                    e["action"] = "omit"
                else:
                    e["action"], e["value"] = "replace", 10              # "an integer from 1 to 600": a number, as written
                if '"reason"' in how:
                    e["reason"] = "answered from the question"
            elif path[-1] == "ruleset":
                if ident == "review":
                    tgt["review"] = "accepted"
                else:
                    cands = re.search(r"to check: ([a-z0-9-]+)", text)
                    tgt["stock"][ident.split("/", 1)[1]].update(integration=cands.group(1) if cands else None,
                                                                selection={"process.name": "sshd"} if '"selection"' in how else None)
            elif path[-1] == "ssh-access":
                next(e for e in tgt if e["id"] == ident).update(user="root", key="/root/.ssh/k")
            else:
                next(e for e in tgt if e["id"] == ident)["action"] = "confirm" if path[-1] == "point-of-no-return" else "activate-force"
            n += 1
        json.dump(d, open(f, "w"))
    return n


class UserSessionWalkF7(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="f7-walk-")
        self.addCleanup(shutil.rmtree, self.t, True)
        os.makedirs(os.path.join(self.t, "rules", "ruleset", "rules"))
        open(os.path.join(self.t, "rules", "ruleset", "rules", "0095-sshd_rules.xml"), "w").write(F7.SSHD_RULES)
        os.makedirs(os.path.join(self.t, "rmig", "rmig", "data"))
        json.dump(F7.INDEX5, open(os.path.join(self.t, "rmig", "rmig", "data", "stock5-index.json"), "w"))
        self.walker = os.path.join(self.t, "walker.py")
        open(self.walker, "w").write(WALKER)
        self.log = os.path.join(self.t, "children.log")
        self.wargs = " ".join([SRC, F7.FX, F7.STOCK, F7.BASE, os.path.join(self.t, "rules"), os.path.join(self.t, "rmig"), "'%s'" % F7.ALL_RUN])

    def stub(self, cluster):
        x = ' "${NX_DEC[0]}" wazuh-1' if cluster else ""
        w = "python3 %s %s" % (self.walker, self.wargs)
        return ('nx_child() { echo "$*" >> %s; mkdir -p "$STATE"\n'
                '  case "$*" in\n'
                '    "run --through precopy") %s precopy "$MIGRATION_DECISIONS" "$STATE"%s;;\n'
                '    run) %s run "$MIGRATION_DECISIONS" "$STATE";;\n'
                '    confirm-no-return) stamp confirm.no_return;;\n'
                '    agents) stamp phase.agents;;\n'
                '    finish) %s finish "$MIGRATION_DECISIONS" "$STATE"%s;;\n'
                '    raw-ask) %s raw-ask "$MIGRATION_DECISIONS" "$STATE"%s;;\n'
                '    *) return 9;;\n'
                '  esac; }\n') % (self.log, w, x, w, w, x, w, x)

    def walk(self, sh, env, files, cluster=False, limit=8):
        commands = rounds = 0
        pre = 'rm -rf "$STATE"; ' if cluster else ""                     # the master has no all-in-one run
        while commands < limit:
            rc, out = sh.run(pre + self.stub(cluster) + "cmd_next", env=env, timeout=180)
            commands += 1
            if rc == 0:
                self.assertIn("MIGRATION FINISHED", out)
                return commands, rounds
            self.assertEqual(rc, 3, out[-3000:])                            # only questions, never a failure
            self.assertNotIn("REFUSED", out)                                # no answer of the round before was refused
            self.assertNotIn("FAIL", out)
            self.assertGreater(person(files, out), 0, out[-2000:])
            rounds += 1
        self.fail("no end after %d commands" % limit)

    def test_a_clean_all_in_one_in_3_commands_and_2_rounds(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        inp = os.path.join(sh.tmp, "inputs")
        os.makedirs(os.path.join(inp, "rm", "rmig"))
        for x in ("files.tar", "id.py"):
            open(os.path.join(inp, x), "w").close()
        env = {"V4_INSTALL_FILES_TAR": os.path.join(inp, "files.tar"), "IDENTITY_TOOL": os.path.join(inp, "id.py"),
               "RMIG_DIR": os.path.join(inp, "rm"), "CLUSTER_HOME": os.path.join(sh.tmp, "ch"), "WM_SELF": "./wazuh-migrate.sh"}
        self.assertEqual(self.walk(sh, env, [os.path.join(sh.bundle, "decisions.json")]), (3, 2))
        self.assertEqual(open(self.log).read().split("\n")[:2], ["run --through precopy", "run --through precopy"])

    def test_a_clean_cluster_from_its_master_in_4_commands_and_3_rounds(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        os.makedirs(os.path.join(sh.root, "var/ossec/etc"))
        open(os.path.join(sh.root, "var/ossec/etc/ossec.conf"), "w").write(TOC.ClusterDetection.CONF % ("wazuh-1", "master", "no"))
        ci = TOC.ClusterInventory()
        ci.t = sh.tmp
        tar = ci.tar()
        os.makedirs(os.path.join(sh.tmp, "rm", "rmig"))
        open(os.path.join(sh.tmp, "id.py"), "w").close()
        home = os.path.join(sh.tmp, "ch")
        env = {"CLUSTER_HOME": home, "V4_INSTALL_FILES_TAR": tar, "IDENTITY_TOOL": os.path.join(sh.tmp, "id.py"),
               "RMIG_DIR": os.path.join(sh.tmp, "rm"), "WM_SELF": "./wazuh-migrate.sh"}
        self.assertEqual(self.walk(sh, env, [os.path.join(home, "decisions.json")], cluster=True), (4, 3))
        d = json.load(open(os.path.join(home, "decisions.json")))
        self.assertIn("settings", d["nodes"]["wazuh-1"])                  # the node's questions, answered in the one file
        self.assertEqual(d["nodes"]["wazuh-1"]["unclassified-finish"][0]["action"], "activate-force")


if __name__ == "__main__":
    unittest.main()
