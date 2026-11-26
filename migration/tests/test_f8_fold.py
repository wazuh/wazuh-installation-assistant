"""F8 fold (2026-11-25 night): the last fold before the test day. What the person reads at the pre-copy stop of a
cluster: one decisions file named (the controller's), no environment variable, no instruction of the ruleset tool's
own, one question per duplicate option, customer wording for the removed sections, and a later command that does not
print the whole assessment again. Each case was run against the tree before the fold too: see the fold's evidence."""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import helpers

SRC = helpers.SRC
FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "settings")
SS = helpers.load(os.path.join(SRC, "settings_stage.py"), "settings_stage_f8")
NF = helpers.load(os.path.join(SRC, "next_flow.py"), "next_flow_f8")
BASE = os.path.join(SRC, "converter", "refs", "base-5.0.0-aio")
STOCK = os.path.join(SRC, "converter", "refs", "stock-4.14.10-ubuntu24")
SYSLOG = "ossec.conf:/ossec_config[3]/syslog_output[1]"
DUP = "ossec.conf:/ossec_config/remote/queue_size"
F6 = helpers.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_f6_fold.py"), "test_f6_fold_f8")
CL1 = helpers.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_cl1_cluster.py"), "test_cl1_cluster_f8")
INTERNAL = re.compile(r"RMIG_DECISIONS|RMIG_DIR|RM-[A-Z]-[A-Z]|run plan again|\(rmig's|rmig's decisions\.json|\"action\": null|"
                      r"reconcile a working copy|with the owners|\.md but")


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


FAKE_RMIG = r'''import json, os, sys
a = sys.argv[1:]
w = a[a.index("--workdir") + 1]
os.makedirs(w, exist_ok=True)
json.dump({"version": 1, "stock": {"rule:5716": {"integration": None, "selection": None, "used_by": ["rule:100300"]}},
           "fields": {"x.y": {"action": None, "required": False}}}, open(os.path.join(w, "decisions.json"), "w"))
open(os.path.join(w, "report.md"), "w").write("""# Ruleset migration report

## Review before activate (mandatory)

Most detection is in stock. The review is mandatory: `activate` stops (`RM-P-REVIEW-PENDING`) until decisions.json has `"review": "accepted"`.

| Custom rules | Count | Recommendation |
|---|---:|---|
| Migrate | 1 | Built in out/ (a silencer as part of the rule it silences). Apply, verify, then activate. |
| Needs your decision | 1 | Answer the entries of decisions.json, then run plan again. |
| Manual recipe | 0 | Follow the recipe of each one (out/recipes/). |

## Summary
""")
print("migrate: questions open")
sys.exit(1)
'''


def helpers_write(p, text):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


class TheMastersRulesetLinesNameTheControllersFileF8(F6.RmigFollowUpQuestionsItem2):
    """E9-cluster-deb 1 and 3: the master's ruleset step said "answer the "ruleset" section of
    /root/wazuh-migration-bundle/decisions.json (rmig's decisions.json; ...) and run again (RMIG_DECISIONS still names a
    file of its own)": the node's copy and an environment variable. The review block it printed said "Answer the entries
    of decisions.json, then run plan again" and "`activate` stops (`RM-P-REVIEW-PENDING`)": the ruleset tool's own
    commands. Every line now names the file the person answers (the controller's, DECISIONS_SHOWN) and this tool."""

    SHOWN = "/root/wazuh-migration-cluster/decisions.json"

    def test_the_stop_names_the_controllers_file_and_this_tool(self):
        # rmig exits 1 (questions open) only on content this fixture lacks: a stand-in that does, with rmig's own block
        sh = self.shell(SRC)
        fake = os.path.join(sh.tmp, "rmig-fake")
        helpers_write(os.path.join(fake, "rmig", "__init__.py"), "")
        helpers_write(os.path.join(fake, "rmig", "__main__.py"), FAKE_RMIG)
        rc, out = self.build(sh, {"DECISIONS_SHOWN": self.SHOWN, "WM_SELF": "./wazuh-migrate.sh", "RMIG_DIR": fake})
        self.assertEqual(rc, 3, out)
        self.assertEqual(INTERNAL.findall(out), [], out)
        self.assertIn('decisions: the ruleset questions are in %s, section "ruleset"' % self.SHOWN, out)
        self.assertIn('ruleset questions are open: answer them in %s, section "ruleset"' % self.SHOWN, out)
        self.assertIn("run ./wazuh-migrate.sh again", out)
        self.assertNotIn(os.path.join(sh.bundle, "decisions.json"), out)          # never the node's copy

    def test_the_review_block_says_this_tools_steps(self):
        sh = self.shell(SRC)
        rc, out = self.build(sh, {"DECISIONS_SHOWN": self.SHOWN, "WM_SELF": "./wazuh-migrate.sh"})
        block = out[out.index("review ("):out.index("the whole report:")]
        self.assertIn("Answer the questions listed under QUESTION, then run ./wazuh-migrate.sh again.", block)
        self.assertIn('the migrated rules are not activated until "review" is "accepted" in %s' % self.SHOWN, block)
        self.assertNotIn("`", block)

    def test_the_open_review_names_no_code(self):
        sh = self.shell(SRC)
        rc, out = self.build(sh, {"DECISIONS_SHOWN": self.SHOWN, "WM_SELF": "./wazuh-migrate.sh"})
        d = self.flow(sh)
        d["ruleset"]["stock"]["rule:80700"].update(integration="auditd", selection="wazuh.integration.name: auditd")
        self.set_flow(sh, d)
        rc, out = self.build(sh, {"DECISIONS_SHOWN": self.SHOWN, "WM_SELF": "./wazuh-migrate.sh"})
        self.assertEqual(rc, 3, out)
        self.assertIn("RULESET REVIEW OPEN: the migrated rules are not activated until you accept the review", out)
        self.assertEqual(INTERNAL.findall(out), [], out)

    test_the_new_question_reaches_the_flow_file_and_the_step_stays_open = None
    test_once_answered_the_rule_is_built = None
    test_a_file_of_the_users_own_gets_the_question = None
    test_without_the_change_the_step_is_done_and_the_rule_left_out = None


class TheClustersStopLineIsNotActionNullF8(unittest.TestCase):
    """E9-cluster-deb 2: "answer the open entries ("action": null)" sent the person to every null entry of the ruleset
    section, where fields.* and lists.* entries with action null and required false are not questions. The stop now
    points to the questions listed under QUESTION, and names this tool's command (WM_SELF reaches every node step)."""

    def test_the_stop_line_and_the_node_environment(self):
        c = CL1.Cluster()
        self.addCleanup(c.close)
        node = {"settings": {"x": {"action": None, "question": {"option": "remote.queue_size", "asks": "a value 5.0 refuses"}}}}
        rc, out, calls = c.run("run", "--only", "precopy", DECISIONS=json.dumps(node), FAIL_PAT="settings-node.sh plan-precopy", FAIL_RC="3",
                               WM_SELF="./wazuh-migrate.sh")
        self.assertEqual(rc, 3, out[-3000:])
        cdec = os.path.join(c.t, "decisions.json")
        self.assertIn("answer the questions listed under QUESTION at the end of this run, in %s (node wazuh-1's" % cdec, out)
        self.assertNotIn('"action": null', out)
        self.assertIn("and run ./wazuh-migrate.sh again", out)
        self.assertTrue(any("WM_SELF=./wazuh-migrate.sh" in x and "settings-node.sh" in x for x in calls), calls[:5])


class OneQuestionPerDuplicateInCustomerWordsF8(unittest.TestCase):
    """E9-cluster-deb 4: a duplicate option (remote/queue_size twice) was two questions, one per copy, each saying
    "Duplicate child; reconcile a working copy before rerunning"; the removed syslog_output section said "The guide
    points to remote-syslog-output.md ... Select an alternative with the owners". One question per duplicate now, and
    both say what happens and what the answer does, in the person's words."""

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="f8-settings-")
        self.v4 = os.path.join(self.t, "v4")
        shutil.copytree(os.path.join(FX, "e1x-aio"), self.v4)
        os.unlink(os.path.join(self.v4, "decisions.json"))
        conf = os.path.join(self.v4, "ossec.conf")
        text = open(conf).read()
        self.assertIn("    <queue_size>262144</queue_size>\n", text)
        open(conf, "w").write(text.replace("    <queue_size>262144</queue_size>\n",
                                           "    <queue_size>262144</queue_size>\n    <queue_size>131072</queue_size>\n", 1))
        self.groups = os.path.join(self.t, "groups4")
        shutil.copytree(os.path.join(FX, "groups"), self.groups)
        self.dec = os.path.join(self.t, "decisions.json")
        self.addCleanup(shutil.rmtree, self.t, True)
        SS.REFUSED[:] = []

    def plan(self):
        return quiet(SS.main, ["plan", "--v4", self.v4, "--stock", STOCK, "--base", BASE, "--decisions", self.dec,
                               "--work", os.path.join(self.t, "work"), "--groups", self.groups])

    def test_one_question_for_both_copies_answered_once(self):
        rc, out = self.plan()
        self.assertEqual(rc, 3, out)
        d = json.load(open(self.dec))
        dups = [k for k in d["settings"] if "queue_size" in k]
        self.assertEqual(dups, [DUP], out)
        self.assertEqual(len(d["settings"][DUP]["covers"]), 2)
        self.assertEqual(list(d["settings"][DUP]["question"]["answers"]), ["omit"])
        for k, e in d["settings"].items():
            if e.get("action") is None:
                e.update(action="omit", reason="r") if "day_wait" not in k else e.update(action="replace", value=10, reason="r")
        json.dump(d, open(self.dec, "w"))
        rc, out = self.plan()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("REFUSED", out)

    def test_the_questions_are_in_customer_words(self):
        rc, out = self.plan()
        qs = {q[1]: q[2] for q in NF.open_questions(json.load(open(self.dec)))}
        self.assertIn("sets remote/queue_size 2 times where 5.0 accepts it once", qs[DUP])
        self.assertIn("5.0 has no syslog_output section", qs[SYSLOG])
        for text in (qs[DUP], qs[SYSLOG], out):
            self.assertEqual(INTERNAL.findall(text), [], text)


class VersionSaysWhereTheRulesetToolIsAskedF8(unittest.TestCase):
    """E9-cluster-deb 5: --version said "the run asks for RMIG_DIR", an environment variable the person never sets."""

    def test_version(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        out = os.path.join(t, "wazuh-migrate.sh")
        p = subprocess.run(["bash", os.path.join(SRC, "build-wazuh-migrate.sh"), "--out", out], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(p.returncode, 0, p.stdout.decode())
        v = subprocess.run(["bash", out, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()
        self.assertIn("the run asks where the ruleset tool is", v)
        self.assertNotIn("RMIG_DIR", v)
        self.assertNotIn("IDENTITY_TOOL", v)


class TheInputQuestionNamesNoVariableF8(unittest.TestCase):
    """The question for a missing input said "(or set RMIG_DIR in the environment)": the decisions file is the answer."""

    def test_input_question(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        dec = os.path.join(t, "decisions.json")
        rc, _ = quiet(NF.cmd_inputs, dec, "RMIG_DIR=" + os.path.join(t, "nowhere"))
        self.assertEqual(rc, 3)
        e = NF.flow_entry(NF.load(dec), "inputs", "RMIG_DIR")
        self.assertNotIn("RMIG_DIR", e["answer"] + e["question"])


class ALaterCommandDoesNotPrintTheWholeAssessAgainF8(unittest.TestCase):
    """E9-cluster-deb 6: run 3 printed the 28-second assessment again in full (48 lines) before the pre-copy steps it
    skips. Assess still runs (the source can change between commands), but once it has passed, a later command prints
    only blockers, warnings and one count line; every check goes to the logs' assess-again.log."""

    def test_the_second_assess_is_short(self):
        c = CL1.Cluster()
        self.addCleanup(c.close)
        rc, first, _ = c.run("run", "--through", "assess")
        self.assertEqual(rc, 0, first[-3000:])
        self.assertIn("PASS  node wazuh-1", first)
        rc, again, _ = c.run("run", "--through", "assess")
        self.assertEqual(rc, 0, again[-3000:])
        self.assertNotIn("PASS  ", again)
        self.assertNotIn("info  facts", again)
        self.assertRegex(again, r"assess: \d+ check\(s\) passed as before, 0 blocker\(s\)")
        log = open(os.path.join(c.t, "st", "logs", "assess-again.log")).read()
        self.assertIn("PASS  node wazuh-1", log)
        rc, only, _ = c.run("run", "--only", "assess")
        self.assertIn("PASS  node wazuh-1", only)                                    # asked for by name: in full

    def test_a_blocker_is_still_printed(self):
        c = CL1.Cluster()
        self.addCleanup(c.close)
        rc, first, _ = c.run("run", "--through", "assess")
        self.assertEqual(rc, 0, first[-3000:])
        rc, again, _ = c.run("run", "--through", "assess", FAIL_PAT="source-version.sh", FAIL_RC="1")
        self.assertNotEqual(rc, 0, again[-3000:])
        self.assertIn("FAIL  ", again)



# ======================================================================== E8-cluster-rpm (ran 9e745af5; each checked here)
TOC = helpers.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_one_command.py"), "test_one_command_f8")
ALL_RUN = TOC.ALL_RUN
CLUSTER_RUN = "phase.assess phase.precopy phase.freeze phase.verify_bundle phase.indexers phase.master phase.import phase.open phase.workers phase.verify phase.history"


class BackMasterAfterTheImportImportsAgainF8(unittest.TestCase):
    """E8-cluster-rpm fix 02 (blocker): 'back master' after the import cleared only the master's own markers; the next run
    reinstalled the master, said "PHASE 7 import: already complete, skipped", opened a 5.0 master with an empty registry
    and removed the worker's 4.x before its gate stopped. The import and the opening are cleared with the master."""

    def test_forward_after_back_master_imports_and_opens_again(self):
        c = CL1.Cluster()
        self.addCleanup(c.close)
        rc, out, _ = c.run("run", "--through", "open")
        self.assertEqual(rc, 0, out[-2000:])
        rc, out, _ = c.run("back", "master")
        self.assertEqual(rc, 0, out[-2000:])
        for m in ("phase.import", "phase.open", "import.identity", "open.listeners"):
            self.assertFalse(os.path.exists(os.path.join(c.t, "st", "state", m)), m)
        rc, out, calls = c.run("run", "--through", "open")
        self.assertEqual(rc, 0, out[-2000:])
        self.assertNotIn("import: already complete", out)
        st = [s for _, s in CL1.Cluster.steps(calls)]
        self.assertTrue(any(s.startswith("identity-stage-master.sh") for s in st), st)
        self.assertTrue(any(s.startswith("open-node.sh") for s in st), st)


class AnEarlierAttemptsConfirmIsNeverReadF8(unittest.TestCase):
    """E8-cluster-rpm gap 3 (unsafe): after a whole way back and a restart, the earlier attempt's point-of-no-return entry
    stayed in the decisions file. The one command showed it before the freeze, and answered "confirm" as printed it would
    have skipped the next point-of-no-return stop. Before this attempt froze 4.x, every point-of-no-return and finish
    answer is set aside (kept under "earlier-attempts", never read); after it, a point-of-no-return entry written for
    another attempt is set aside too. All-in-one and cluster."""

    STALE = {"point-of-no-return": [{"id": "confirm-no-return", "action": "confirm", "choices": ["confirm"]}],
             "unclassified-finish": [{"id": "raw-at-finish", "action": "accept-loss"}],
             "ruleset": {"version": 1, "review": "accepted"}}

    def aio(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        files = os.path.join(sh.tmp, "inputs")
        os.makedirs(os.path.join(files, "rm", "rmig"))
        for f in ("files.tar", "id.py"):
            open(os.path.join(files, f), "w").close()
        env = {"V4_INSTALL_FILES_TAR": os.path.join(files, "files.tar"), "IDENTITY_TOOL": os.path.join(files, "id.py"),
               "RMIG_DIR": os.path.join(files, "rm"), "CLUSTER_HOME": os.path.join(sh.tmp, "cluster-home"), "WM_SELF": "./wazuh-migrate.sh",
               "MARK_run_precopy": "phase.precopy", "MARK_run": ALL_RUN}
        return sh, env

    def children(self, sh):
        p = os.path.join(sh.bundle, "children.log")
        return open(p).read().splitlines() if os.path.exists(p) else []

    def test_all_in_one_a_new_bundle_with_an_old_confirm(self):
        sh, env = self.aio()
        sh.write("decisions.json", self.STALE)
        rc, out = sh.run(TOC.STUB + "cmd_next", env=env)
        self.assertEqual(rc, 3, out)
        self.assertIn("POINT OF NO RETURN", out)
        self.assertNotIn("confirm-no-return", self.children(sh))          # the stop was not skipped
        d = json.load(open(os.path.join(sh.bundle, "decisions.json")))
        self.assertIsNone(d["point-of-no-return"][0]["action"])
        self.assertEqual(d["ruleset"]["review"], "accepted")              # other answers stay
        self.assertEqual({m["section"] for m in d["earlier-attempts"]}, {"point-of-no-return", "unclassified-finish"})

    def test_all_in_one_a_confirm_of_another_outage(self):
        sh, env = self.aio()
        for m in ALL_RUN.split():
            sh.write("state/" + m, "t")
        sh.write("decisions.json", self.STALE)                            # past this attempt's freeze, but not its answer
        rc, out = sh.run(TOC.STUB + "cmd_next", env=env)
        self.assertEqual(rc, 3, out)
        self.assertNotIn("confirm-no-return", self.children(sh))
        d = json.load(open(os.path.join(sh.bundle, "decisions.json")))
        d["point-of-no-return"][0]["action"] = "confirm"                  # the answer to this attempt's question
        json.dump(d, open(os.path.join(sh.bundle, "decisions.json"), "w"))
        rc, out = sh.run(TOC.STUB + "cmd_next", env=dict(env, MARK_confirm_no_return="confirm.no_return", MARK_agents="phase.agents", MARK_finish="phase.finish"))
        self.assertEqual(rc, 0, out)
        self.assertIn("confirm-no-return", self.children(sh))

    def test_cluster_restart_with_an_old_confirm(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        home = os.path.join(sh.tmp, "ch")
        os.makedirs(home)
        inv = {"ssh": {"user": "root", "key": "/root/.ssh/k"}, "state_dir": os.path.join(home, "cluster-state-2"),
               "nodes": [dict(n) for n in CL1.Cluster.NODES], "inputs": {}, "settings": {}}
        json.dump(inv, open(os.path.join(home, "inventory.json"), "w"))
        stale = dict(self.STALE, nodes={"wazuh-1": {"unclassified-finish": [{"id": "raw-at-finish", "action": "keep-raw"}]}})
        json.dump(stale, open(os.path.join(home, "decisions.json"), "w"))
        env = {"CLUSTER_HOME": home, "WM_SELF": "./wazuh-migrate.sh", "MARK_run_precopy": "phase.precopy", "MARK_run": CLUSTER_RUN}
        rc, out = sh.run(TOC.STUB + "cmd_next", env=env)
        self.assertEqual(rc, 3, out)
        self.assertIn("POINT OF NO RETURN", out)
        self.assertNotIn("confirm-no-return", self.children(sh))
        d = json.load(open(os.path.join(home, "decisions.json")))
        self.assertIsNone(d["point-of-no-return"][0]["action"])
        self.assertNotIn("unclassified-finish", d["nodes"]["wazuh-1"])


class CommandsPrintedAreTheOneFilesF8(unittest.TestCase):
    """E8-cluster-rpm gaps 4, 5, 12: the stop of a failed master install named
    '/root/.wazuh-migrate.XXXX/src/migrate-cluster.sh --inventory … back master' and '… run', inside the one file's
    extraction directory (removed at exit); --help said ./migrate.sh and did not name 'back master'. The commands are
    the one file's own; on the master the point-of-no-return question's 'back' goes back the cluster."""

    def test_the_failed_master_install_names_the_one_file(self):
        c = CL1.Cluster()
        self.addCleanup(c.close)
        rc, out, _ = c.run("run", FAIL_PAT="install5.sh -wm", FAIL_RC="1", WM_SELF="./wazuh-migrate.sh")
        self.assertNotEqual(rc, 0)
        inv = os.path.join(c.t, "inv.json")
        self.assertIn("'./wazuh-migrate.sh cluster --inventory %s back master'" % inv, out)
        self.assertNotIn("migrate-cluster.sh --inventory", out)

    def test_on_the_master_the_question_says_back_and_back_goes_back_the_cluster(self):
        t = tempfile.mkdtemp(prefix="f8-ponr-")
        self.addCleanup(shutil.rmtree, t, True)
        dec = os.path.join(t, "decisions.json")
        quiet(NF.cmd_no_return, dec, "./wazuh-migrate.sh", "cluster", "s t")
        q = NF.load(dec)["point-of-no-return"][0]["question"]
        cmd = re.search(r"Until you confirm, '([^']+)'", q).group(1)
        self.assertEqual(cmd, "./wazuh-migrate.sh back")
        src = os.path.join(t, "src")
        shutil.copytree(SRC, src, ignore=shutil.ignore_patterns("__pycache__"))
        open(os.path.join(src, "migrate-cluster.sh"), "w").write('echo "CLUSTER $*"\n')
        home = os.path.join(t, "home")
        os.makedirs(home)
        open(os.path.join(home, "inventory.json"), "w").write("{}")
        env = dict(os.environ, CLUSTER_HOME=home, BUNDLE_DIR=os.path.join(t, "bundle"), WORK_DIR=os.path.join(t, "work"))
        p = subprocess.run(["bash", os.path.join(src, "migrate.sh")] + cmd.split()[1:], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertIn("CLUSTER --inventory %s back" % os.path.join(home, "inventory.json"), p.stdout.decode())

    def test_help_names_the_one_file_and_back_master(self):
        p = subprocess.run(["bash", os.path.join(SRC, "migrate.sh"), "--help"], env=dict(os.environ, WM_SELF="./wazuh-migrate.sh"),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode()
        self.assertIn("./wazuh-migrate.sh back master", out)
        self.assertNotIn("./migrate.sh", out)


class SmallItemsE8ClusterRpmF8(unittest.TestCase):
    """E8-cluster-rpm gaps 7 and 10: a 4.14.10 source, refused by the version check, was also told "source build 4.14.10
    is newer than the builds this script was validated on (4.14.11)"; the worker gate, both registries empty, printed
    two equal digests and said they differ."""

    def test_an_older_build_gets_no_newer_warning(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        rc, out = sh.run('VALIDATED_4X="4.14.11"; for v in 4.14.10 4.14.11 4.14.12; do validated_note $v; done')
        self.assertEqual(rc, 0, out)
        self.assertNotIn("4.14.10", out)
        self.assertIn("PASS  source build 4.14.11", out)
        self.assertIn("WARN  source build 4.14.12 is newer", out)

    def test_both_registries_empty_is_said_as_such(self):
        body = open(os.path.join(SRC, "migrate-cluster.sh")).read()
        fn = body[body.index("wk_registry() {"):body.index("return 1; }", body.index("wk_registry() {")) + len("return 1; }")]
        code = fn + '\nregsum() { printf "" | sha256sum | cut -c1-16; }; W=wazuh-2; MASTER=wazuh-1; REGISTRY_TRIES=1 REGISTRY_WAIT=0 wk_registry\n'
        p = subprocess.run(["bash", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("both EMPTY", out)
        self.assertNotIn("does not equal", out)



# ======================================================================== E9-aio (tree 2b920fd6, the fold's base)
BS = helpers.load(os.path.join(SRC, "bundle_secrets.py"), "bundle_secrets_f8")
FU = helpers.load(os.path.join(SRC, "fleet-upgrade.py"), "fleet_upgrade_f8")
H8 = helpers.load(os.path.join(SRC, "mig_helper.py"), "mig_helper_f8")


class TheFirstAttemptsRulesetStepOnTheClusterNodeF8(unittest.TestCase):
    """E9-aio fix 01 on the cluster's path: the master's ruleset-node.sh runs the same im_ruleset under common.sh's
    errexit and pipefail (tests/test_e9_fix01.py covers the all-in-one step). On a first attempt it reaches the
    verification."""

    def test_node_path_first_attempt(self):
        t = tempfile.mkdtemp(prefix="f8-node-")
        self.addCleanup(shutil.rmtree, t, True)
        b = os.path.join(t, "b")
        os.makedirs(os.path.join(b, "v4", "alerts"))
        os.makedirs(os.path.join(b, "work", "ruleset-migration"))
        open(os.path.join(b, "v4", "alerts", "alerts.json"), "w").write("{}")
        open(os.path.join(b, "work", "ruleset-migration", "ENGINE_HELPERS"), "w").write("5.0\n")
        code = ('. "$SRC/cluster/node/common.sh"; aio_lib; rmig() { echo "RMIG $*"; }; rmig_dialect_installed() { echo 5.0; }; '
                'im_ruleset; echo STEP-END')
        p = subprocess.run(["bash", "-c", code], env=dict(os.environ, BUNDLE_DIR=b, MIG_HOME=os.path.join(t, "h"), SRC=SRC),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode()
        self.assertEqual(p.returncode, 0, out)
        self.assertIn("STEP-END", out)
        self.assertIn("RMIG verify", out)


class NoFailingCommandSubstitutionUnderPipefailF8(unittest.TestCase):
    """E9-aio item 0's sweep: under `set -Eeuo pipefail` an assignment from a pipeline whose first command finds nothing
    (ls on a glob that matches nothing, grep with no match) ends the step with no message. Every such assignment in the
    shipped bash takes its value whatever that command returns (`|| true`, or a loop)."""

    RX = re.compile(r"=\$\((ls|grep)\b[^)]*\|")

    def test_none_left(self):
        bad = []
        for root, _, files in os.walk(SRC):
            for fn in files:
                if not fn.endswith(".sh"):
                    continue
                for n, l in enumerate(open(os.path.join(root, fn), errors="replace"), 1):
                    if l.strip().startswith("#"):
                        continue
                    for m in self.RX.finditer(l):
                        seg = l[m.start():]
                        if not re.search(r"\|\|\s*(true|echo|:)", seg.split(";")[0] + seg[:300]):
                            bad.append("%s:%d: %s" % (os.path.relpath(os.path.join(root, fn), SRC), n, l.strip()[:120]))
        self.assertEqual(bad, [])


class AStepThatErrexitEndsNamesItsCauseF8(unittest.TestCase):
    """E9-aio item 1: the ruleset step ended with exit 2 and a log that ended at "rmig apply exit 0": nothing said what
    failed, yet the run said "fix the cause". A step body that errexit ends writes the command and the line to its log;
    the FAIL line and the one command's FAILED line repeat it."""

    def test_the_trap_names_the_command(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        rc, out = sh.run('f_() { x=$(false) || true; z=$(ls /nonexistent-f8-* 2>/dev/null | tr "a" "b"); echo NOT-REACHED; }; '
                         'set -Eeuo pipefail; trap "$STEP_ERR_TRAP" ERR; f_')
        self.assertNotEqual(rc, 0)
        self.assertNotIn("NOT-REACHED", out)
        stops = [l for l in out.splitlines() if "STEP STOPPED:" in l]
        self.assertEqual(len(stops), 1, out)                 # the tolerated failure is not reported
        self.assertIn("ls /nonexistent-f8-*", stops[0])
        self.assertIn("in f_", stops[0])

    def test_every_step_shell_sets_it_and_the_failure_line_repeats_it(self):
        self.assertIn('trap - ERR; set -Eeuo pipefail; trap "$STEP_ERR_TRAP" ERR; "$1"; exit 0', open(os.path.join(SRC, "migrate.sh")).read())
        self.assertIn('trap "$STEP_ERR_TRAP" ERR; "$1"; exit 0', open(os.path.join(SRC, "migrate-cluster.sh")).read())
        self.assertIn("STEP STOPPED:", open(os.path.join(SRC, "cluster", "node", "common.sh")).read())
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        json.dump({"step": "import.ruleset", "description": "ruleset", "exit": 2, "result": "failed"}, open(os.path.join(t, "import.ruleset.json"), "w"))
        open(os.path.join(t, "import.ruleset.log"), "w").write("rmig apply exit 0\nSTEP STOPPED: the command \"x\" exited 2 (line 9 of migrate.sh, in im_ruleset)\n")
        rc, out = quiet(NF.cmd_last_failure, t)
        self.assertIn('it stopped at: the command "x" exited 2 (line 9 of migrate.sh, in im_ruleset)', out)


class TheWayBackKeepsTheAlertsSampleF8(unittest.TestCase):
    """E9-aio item 2: the way back deleted v4/alerts with the bundle's carried parts, so attempt-1 kept no 4.x alert and
    the next attempt's verification had no samples from it. The way back keeps them as v4/alerts-sample (searched like
    the rest; a file holding a carried value is deleted), and the verification reads them."""

    def test_the_sweep_keeps_the_sample(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        b = os.path.join(t, "bundle")
        os.makedirs(os.path.join(b, "v4", "alerts"))
        os.makedirs(os.path.join(b, "v4", "etc"))
        open(os.path.join(b, "v4", "alerts", "alerts.json"), "w").write('{"rule": {"id": "100300"}}\n')
        rc, out = quiet(BS.sweep, b, (), (), False, [os.path.join(t, "none")], True)
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isfile(os.path.join(b, "v4", "alerts-sample", "alerts.json")), out)
        self.assertFalse(os.path.exists(os.path.join(b, "v4", "alerts")))
        self.assertFalse(os.path.exists(os.path.join(b, "v4", "etc")))         # the carried parts still go
        self.assertIn("--keep-sample", open(os.path.join(SRC, "migrate.sh")).read())
        self.assertIn("finish-node.sh secrets keep-sample", open(os.path.join(SRC, "migrate-cluster.sh")).read())

    def test_the_verification_reads_the_kept_sample(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        sh.write("v4/alerts/alerts.json", "{}")
        sh.write("v4/alerts-sample/alerts.json", "{}", base=sh.bundle + ".attempt-1")
        sh.write("work/ruleset-migration/ENGINE_HELPERS", "5.0\n")
        rc, out = sh.run('rmig() { echo "RMIG $*"; }; rmig_dialect_installed() { echo 5.0; }; set -Eeuo pipefail; trap - ERR; im_ruleset')
        self.assertEqual(rc, 0, out)
        line = [l for l in out.splitlines() if l.startswith("RMIG verify")][0]
        self.assertIn(os.path.join(sh.bundle + ".attempt-1", "v4", "alerts-sample", "alerts.json"), line)


class LeaksTheE9RunsSawF8(unittest.TestCase):
    """E9-aio item 4: "(rules 21, 22)" in an outage step's name, RMIG_DIR in --version, "(RMIG_DECISIONS still names a
    file of its own)" at the first stop, BUNDLE_DIR at the end of the way back, HISTORY_LOAD=after-open. The F7 sweep of
    shipped strings now looks for these too."""

    MORE = re.compile(r"\(rules? \d+(, ?\d+)+\)|HISTORY_LOAD=|RMIG_DECISIONS still|asks for RMIG_DIR|new BUNDLE_DIR|"
                      r"state_dir and bundle_dir|'\$0 --inventory|or set %s in the environment")

    def test_none(self):
        F7 = helpers.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_f7_fold.py"), "test_f7_fold_f8")
        F7.CODES = re.compile(F7.CODES.pattern + "|" + self.MORE.pattern)
        self.assertEqual(F7.shipped_strings(SRC), [])


class RulesThatDidNotVerifySayWhyF8(unittest.TestCase):
    """E9-aio item 5: rule 100300 was NOT_REPRODUCED and the stop gave no reason. The raw-at-finish stop (and its
    question) names each rule that did not verify and the reason the ruleset tool gives, without its codes."""

    def test_reasons_in_the_stop(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        rw, st = os.path.join(t, "rw"), os.path.join(t, "state")
        os.makedirs(rw)
        os.makedirs(st)
        json.dump({"rules": [{"rule_id_4x": "100300", "result": "NOT_REPRODUCED", "not_met": ["field event.outcome: expected failure, got success (RM-R-FIELD)"]},
                             {"rule_id_4x": "100202", "result": "NO_SAMPLE", "not_met": ["no 4.14 alert of this rule in the files given"]},
                             {"rule_id_4x": "100100", "result": "REPRODUCED", "not_met": []}]}, open(os.path.join(rw, "verification.json"), "w"))
        open(os.path.join(st, "unclassified.applied"), "w").write("verified-none\nraw\n")
        dec = os.path.join(t, "decisions.json")
        rc, out = quiet(H8.raw_decision, dec, st, rw, "")
        self.assertEqual(rc, 3)
        self.assertIn("why: rule 100300: did not match its 4.x alerts on 5.0 (field event.outcome: expected failure, got success)", out)
        self.assertIn("why: rule 100202: had no 4.x alert to check it against", out)
        self.assertNotIn("100100", "".join(l for l in out.splitlines() if l.startswith("  why")))
        self.assertNotIn("RM-R-", out)
        q = json.load(open(dec))["unclassified-finish"][0]["question"]
        self.assertIn("Not verified: rule 100300", q)


class ProgressLinesSayWhoAndUntilWhenF8(unittest.TestCase):
    """E9-aio item 6 (U9 b): the stop came 17 minutes after the agent left, while the run waited for another agent's
    900 s poll, and the progress lines did not say so. Each line names every agent waited for and when its request is
    due, and when an agent that is not connected is left for a later run."""

    def test_line(self):
        t = 1_000_000
        play = {"003": {"state": "requested", "name": "acme-w-01", "requests": [{"t": t - 100}]},
                "002": {"state": "waiting-for-agent", "name": "acme-m-01", "requests": [{"t": t - 50}]}}
        line = FU.progress_line(play, ["003", "002"], {"poll_interval": 900}, 180, 0, t)
        self.assertIn("003 (acme-w-01) requested, requested 100s ago, due by %s" % FU.iso(t - 100 + 900), line)
        self.assertIn("002 (acme-m-01) not connected", line)
        self.assertIn("left for a later run once the others are done (by %s at the latest), then 180s more" % FU.iso(t + 800), line)


if __name__ == "__main__":
    unittest.main()
