"""F7 fold (2026-11-25 night): the user flow to its target. An all-in-one with no fault reaches MIGRATION FINISHED in
3 commands and 2 answer rounds, a cluster in 4 and 3; every question says all its answer needs; going back, a killed
install, a stopped agent and the verification after going back no longer cost commands or need an environment
variable. Each case was run against the tree before the fold too: see the
fold's evidence."""
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
SS = helpers.load(os.path.join(SRC, "settings_stage.py"), "settings_stage_f7")
NF = helpers.load(os.path.join(SRC, "next_flow.py"), "next_flow_f7")
BASE = os.path.join(SRC, "converter", "refs", "base-5.0.0-aio")
STOCK = os.path.join(SRC, "converter", "refs", "stock-4.14.10-ubuntu24")
SYSLOG = "ossec.conf:/ossec_config[3]/syslog_output[1]"
DAY_WAIT = "local_internal_options.conf:/line[21]/monitord.day_wait"


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


class SettingsQuestionsSayEverythingF7(unittest.TestCase):
    """E7-aio U1: the settings answers were refused twice for reasons the question did not give (a missing "reason";
    "value": 10 where the question says "an integer"), and one removed section (syslog_output) was four questions."""

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="f7-settings-")
        self.v4 = os.path.join(self.t, "v4")
        shutil.copytree(os.path.join(FX, "e1x-aio"), self.v4)
        os.unlink(os.path.join(self.v4, "decisions.json"))
        self.groups = os.path.join(self.t, "groups4")
        shutil.copytree(os.path.join(FX, "groups"), self.groups)
        self.dec = os.path.join(self.t, "decisions.json")
        self.addCleanup(shutil.rmtree, self.t, True)
        SS.REFUSED[:] = []          # one process per run in the tool; one module for every case here

    def plan(self):
        return quiet(SS.main, ["plan", "--v4", self.v4, "--stock", STOCK, "--base", BASE, "--decisions", self.dec,
                               "--work", os.path.join(self.t, "work"), "--groups", self.groups])

    def test_one_removed_section_is_one_question_answered_once(self):
        rc, out = self.plan()
        self.assertEqual(rc, 3, out)
        d = json.load(open(self.dec))
        syslog = [k for k in d["settings"] if "syslog_output" in k]
        self.assertEqual(syslog, [SYSLOG], out)                       # one entry for the section, not format/level/port/server
        self.assertEqual(len(d["settings"][SYSLOG]["covers"]), 4)
        self.assertEqual(list(d["settings"][SYSLOG]["question"]["answers"]), ["omit"])
        qs = NF.open_questions(d)
        self.assertEqual(len([q for q in qs if q[0] == "settings"]), 2, qs)   # day_wait and the section
        d["settings"][SYSLOG].update(action="omit", reason="no remote syslog in 5.0")
        d["settings"][DAY_WAIT].update(action="replace", value=10, reason="in range")   # a JSON number, as the question says
        json.dump(d, open(self.dec, "w"))
        rc, out = self.plan()
        self.assertEqual(rc, 0, out)                                    # every answer taken in one round
        self.assertNotIn("REFUSED", out)

    def test_the_how_line_names_the_reason_and_numbers(self):
        self.plan()
        d = json.load(open(self.dec))
        hows = {q[1]: q[3] for q in NF.open_questions(d) if q[0] == "settings"}
        self.assertIn('"reason"', hows[DAY_WAIT])
        self.assertIn('10 or "10"', hows[DAY_WAIT])
        self.assertIn('"reason"', hows[SYSLOG])
        self.assertIn('"omit"', hows[SYSLOG])
        self.assertNotIn('"keep"', hows[SYSLOG])

    def test_a_section_answer_without_a_reason_is_refused_once_as_the_section(self):
        self.plan()
        d = json.load(open(self.dec))
        d["settings"][SYSLOG].update(action="omit")
        json.dump(d, open(self.dec, "w"))
        rc, out = self.plan()
        self.assertEqual(rc, 3)
        self.assertEqual(out.count("REFUSED ANSWER"), 1, out)
        d = json.load(open(self.dec))
        self.assertIsNone(d["settings"][SYSLOG]["action"])
        self.assertFalse([k for k in d["settings"] if k.startswith(SYSLOG + "/")])


class PrecopyAsksEverythingInOneRoundF7(unittest.TestCase):
    """E7-aio U1: the settings questions came only after the ruleset step passed (one more command), and each question
    stop printed a FAIL line before the QUESTION. A step that asks (exit 3) is noted, the steps after it still run, and
    the phase stops with exit 3 once every question is in the decisions file."""

    def setUp(self):
        self.sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(self.sh.close)
        self.self_sh = os.path.join(self.sh.tmp, "self.sh")
        with open(self.self_sh, "w") as f:
            f.write('set +e\nsource %s "$@"\nset +e +u\n' % self.sh.lib)
            f.write('ask_r() { echo "ruleset asks"; return 3; }\nplain() { echo plain; }\nask_s() { echo "settings asks"; return 3; }\n'
                    'boom() { return 5; }\n')
            f.write('if [ "$CMD" = __step ]; then set -Eeuo pipefail; "$2"; exit 0; fi\n')

    def run_steps(self, body):
        code = 'SELF=%s\nJOURNAL=$BUNDLE_DIR/journal.ndjson\n%s' % (self.self_sh, body)
        return self.sh.run(code)

    def test_both_questions_in_one_round_and_no_fail_line(self):
        rc, out = self.run_steps('qstep s.r "ruleset" ask_r; step s.p "plain" plain; qstep s.s "settings" ask_s; qstep_end; echo NOT-REACHED')
        self.assertEqual(rc, 3, out)
        self.assertIn("ruleset asks", out)
        self.assertIn("settings asks", out)                             # the settings step ran although the ruleset asked
        self.assertNotIn("NOT-REACHED", out)
        self.assertNotIn("FAIL", out)
        self.assertTrue(os.path.exists(os.path.join(self.sh.bundle, "state", "s.p")))
        self.assertFalse(os.path.exists(os.path.join(self.sh.bundle, "state", "s.r")))
        r = json.load(open(os.path.join(self.sh.bundle, "results", "s.r.json")))
        self.assertEqual(r["result"], "question")                       # not a failure: last-failure never names it
        self.assertEqual(NF.cmd_last_failure(os.path.join(self.sh.bundle, "results")), 1)

    def test_a_real_failure_still_stops_at_once(self):
        rc, out = self.run_steps('qstep s.r "ruleset" ask_r; qstep s.b "boom" boom; echo NOT-REACHED')
        self.assertEqual(rc, 5, out)
        self.assertIn("FAIL  boom (exit 5)", out)
        self.assertNotIn("NOT-REACHED", out)

    def test_the_precopy_and_the_cluster_precopy_use_it(self):
        aio = open(os.path.join(SRC, "migrate.sh")).read()
        pc = aio[aio.index("phase_precopy() {"):aio.index("# freeze", aio.index("phase_precopy() {")) if "# freeze" in aio else None]
        self.assertRegex(pc, r"qstep precopy\.ruleset_build")
        self.assertRegex(pc, r"qstep precopy\.settings_plan")
        self.assertLess(pc.index("qstep precopy.settings_plan"), pc.index("qstep_end"))
        self.assertLess(pc.index("qstep_end"), pc.index("step precopy.gate"))
        cl = open(os.path.join(SRC, "migrate-cluster.sh")).read()
        self.assertRegex(cl, r"qstep precopy\.settings ")
        self.assertRegex(cl, r"qstep precopy\.ruleset ")
        self.assertLess(cl.index("qstep precopy.ruleset "), cl.index("qstep_end"))


H = helpers.load(os.path.join(SRC, "mig_helper.py"), "mig_helper_f7")
SSHD_RULES = """<group name="syslog,sshd,">
  <rule id="5700" level="0" noalert="1">
    <decoded_as>sshd</decoded_as>
    <description>SSHD messages grouped.</description>
  </rule>
  <rule id="5716" level="5">
    <if_sid>5700</if_sid>
    <match>^Failed</match>
    <group>authentication_failed,pci_dss_10.2.4,gdpr_IV_35.7.d,</group>
  </rule>
</group>
<group name="audit,">
  <rule id="80700" level="0">
    <decoded_as>auditd</decoded_as>
  </rule>
</group>
"""
INDEX5 = {"integrations": {"system-auth": {"decoders": ["decoder/system-auth/0"]}, "auditd": {"decoders": ["decoder/auditd/0", "decoder/auditd-syscall/0"]},
                           "normalized-authentication": {"decoders": []}, "anthropic": {"decoders": ["decoder/anthropic-audit/0"]},
                           "apache-http": {"decoders": ["decoder/apache-access/0"]}, "cisco-ftd": {"decoders": ["decoder/cisco-ftd-authentication/0"]}}}


class StockQuestionsNameCandidatesF7(unittest.TestCase):
    """E7-aio U1: "fill integration and selection" for stock/rule:5716 and stock/rule:80700, with no 5.0 integration or
    field named anywhere (the answers came from rmig's own example). The question now names the 4.x decoder and
    groups, the 5.0 integrations whose names match (to check), the selection's form and where the 5.0 fields are."""

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="f7-stock-")
        self.addCleanup(shutil.rmtree, self.t, True)
        os.makedirs(os.path.join(self.t, "src", "ruleset", "rules"))
        open(os.path.join(self.t, "src", "ruleset", "rules", "0095-sshd_rules.xml"), "w").write(SSHD_RULES)
        os.makedirs(os.path.join(self.t, "rmig", "rmig", "data"))
        json.dump(INDEX5, open(os.path.join(self.t, "rmig", "rmig", "data", "stock5-index.json"), "w"))
        open(os.path.join(self.t, "rmig", "rmig", "data", "wcs-fields.csv"), "w").write("field\nprocess.name\n")
        self.flow = os.path.join(self.t, "decisions.json")
        json.dump({"ruleset": {"version": 1, "review": None, "stock": {
            "rule:5716": {"integration": None, "selection": None, "used_by": ["rule:100300"]},
            "rule:80700": {"integration": None, "selection": None, "used_by": ["rule:100500"]}}}}, open(self.flow, "w"))

    def test_candidates_reach_the_question(self):
        quiet(H.ruleset_hints, self.flow, os.path.join(self.t, "src"), os.path.join(self.t, "rmig"))
        d = json.load(open(self.flow))
        self.assertNotIn("hints", d["ruleset"])                         # rmig's section stays rmig's
        self.assertEqual(d["ruleset-hints"]["stock/rule:5716"]["candidates"][:2], ["system-auth", "normalized-authentication"])
        self.assertEqual(d["ruleset-hints"]["stock/rule:80700"]["candidates"], ["auditd"])
        qs = {q[1]: q for q in NF.open_questions(d)}
        self.assertIn("system-auth", qs["stock/rule:5716"][2])
        self.assertIn("decoder sshd", qs["stock/rule:5716"][2])
        self.assertIn('"selection"', qs["stock/rule:5716"][3])
        self.assertIn("wcs-fields.csv", qs["stock/rule:5716"][3])
        self.assertIn("auditd", qs["stock/rule:80700"][2])

    def test_every_open_question_is_printed_with_its_how_line(self):
        quiet(H.ruleset_hints, self.flow, os.path.join(self.t, "src"), os.path.join(self.t, "rmig"))
        rc, out = quiet(NF.cmd_question, self.flow)
        self.assertEqual(rc, 0)
        self.assertIn("QUESTION: the stock 4.x rule:5716", out)
        self.assertIn('section "ruleset", "stock/rule:80700"', out)      # the second question, with its own how
        self.assertIn('section "ruleset", "review"', out)
        self.assertEqual(out.count("how:"), 3, out)

    def test_the_cluster_carries_the_hints_to_the_controller_file(self):
        quiet(H.ruleset_hints, self.flow, os.path.join(self.t, "src"), os.path.join(self.t, "rmig"))
        cdec = os.path.join(self.t, "controller.json")
        json.dump({"ssh-access": []}, open(cdec, "w"))
        H.ruleset_carry("from-node", cdec, self.flow)
        c = json.load(open(cdec))
        self.assertIn("stock/rule:5716", c["ruleset-hints"])
        self.assertIn("rule:5716", c["ruleset"]["stock"])


TOC = helpers.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_one_command.py"), "test_one_command_f7")
ALL_RUN = TOC.ALL_RUN


class _OneCommand(unittest.TestCase):
    def setUp(self):
        self.sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(self.sh.close)
        self.dec = os.path.join(self.sh.bundle, "decisions.json")
        self.files = os.path.join(self.sh.tmp, "inputs")
        os.makedirs(os.path.join(self.files, "rm", "rmig"))
        for f in ("files.tar", "id.py"):
            open(os.path.join(self.files, f), "w").close()

    def env(self, extra=None):
        e = {"V4_INSTALL_FILES_TAR": os.path.join(self.files, "files.tar"), "IDENTITY_TOOL": os.path.join(self.files, "id.py"),
             "RMIG_DIR": os.path.join(self.files, "rm"), "CLUSTER_HOME": os.path.join(self.sh.tmp, "cluster-home"),
             "WM_SELF": "./wazuh-migrate.sh"}
        e.update(extra or {})
        return e

    def next(self, extra=None, pre=""):
        return self.sh.run(pre + TOC.STUB + "cmd_next", env=self.env(extra))

    def children(self):
        p = os.path.join(self.sh.bundle, "children.log")
        return open(p).read().splitlines() if os.path.exists(p) else []

    def answer(self, f):
        d = json.load(open(self.dec))
        f(d)
        json.dump(d, open(self.dec, "w"))


class AfterGoingBackANewAttemptStartsF7(_OneCommand):
    """E7-aio U6 (DOC2): after 'back' the one command exited 1, "FATAL: this migration went back to 4.x: start again
    with a new bundle (BUNDLE_DIR) or state_dir", and BUNDLE_DIR had to be set on every later command. Now a new
    attempt starts by itself: the old bundle is kept beside the new one, the answers given then are carried (only the
    point of no return is asked again), and no environment variable is needed."""

    def test_a_new_attempt_with_the_earlier_answers(self):
        self.sh.write("state/back.done", "2026-11-25T18:54:26Z")
        self.sh.write("decisions.json", {"ruleset": {"version": 1, "review": "accepted"},
                                         "settings": {"x": {"action": "omit", "reason": "r"}},
                                         "point-of-no-return": [{"id": "confirm-no-return", "action": None, "choices": ["confirm"]}]})
        self.sh.write("v4/alerts/alerts.json", "{}")
        rc, out = self.next({"MARK_run_precopy": "phase.precopy", "MARK_run": ALL_RUN})
        self.assertEqual(rc, 3, out)                                    # the point of no return of the new attempt
        self.assertNotIn("FATAL", out)
        self.assertIn("NEW ATTEMPT", out)
        old = self.sh.bundle + ".attempt-1"
        self.assertTrue(os.path.exists(os.path.join(old, "state", "back.done")))
        self.assertTrue(os.path.exists(os.path.join(old, "v4", "alerts", "alerts.json")))   # kept: the verification reads it
        self.assertFalse(os.path.exists(os.path.join(self.sh.bundle, "state", "back.done")))
        d = json.load(open(self.dec))
        self.assertEqual(d["ruleset"]["review"], "accepted")
        self.assertEqual(d["settings"]["x"]["action"], "omit")
        self.assertIsNone(d["point-of-no-return"][0]["action"])
        self.assertEqual(self.children(), ["run --through precopy", "run"])
        self.sh.write("state/back.done", "again")                       # a second return: attempt-2, attempt-1 kept
        rc, out = self.next({"MARK_run_precopy": "phase.precopy", "MARK_run": ALL_RUN})
        self.assertTrue(os.path.isdir(self.sh.bundle + ".attempt-2"))
        self.assertTrue(os.path.isdir(old))

    def test_the_verification_reads_the_earlier_attempts_alerts(self):
        self.sh.write("v4/alerts/alerts.json", "{}")
        self.sh.write("v4/alerts/x.json", "{}", base=self.sh.bundle + ".attempt-1")
        self.sh.write("work/ruleset-migration/ENGINE_HELPERS", "5.0\n")
        code = ('rmig() { echo "RMIG $*"; }; rmig_dialect_installed() { echo 5.0; }; mkdir -p /dev/null 2>/dev/null; im_ruleset')
        rc, out = self.sh.run(code)
        self.assertEqual(rc, 0, out)
        line = [l for l in out.splitlines() if l.startswith("RMIG verify")][0]
        self.assertIn(os.path.join(self.sh.bundle, "v4", "alerts", "alerts.json"), line)
        self.assertIn(os.path.join(self.sh.bundle + ".attempt-1", "v4", "alerts", "x.json"), line)


class FewRulesCheckedAreNotActivatedSilentlyF7(_OneCommand):
    """E7-aio forward 2: REPRODUCED 1, NO_SAMPLE 5 activated every rule, including one forward 1 had shown not
    reproduced. With most rules unchecked nothing is activated by default; raw indexing keeps the events, and the
    point-of-no-return stop asks (the same round)."""

    def decide(self, summary, vrc="0"):
        self.sh.write("state/ruleset.verify_summary", summary)
        self.sh.write("state/ruleset.verify_rc", vrc)
        fake = self.sh.write("fake-helper.py", "import sys\nprint('HELPER ' + ' '.join(sys.argv[1:]))\n", base=self.sh.tmp)
        code = 'HELPER=%s; rmig_activate() { echo "ACTIVATED $*"; }; ruleset_clean() { return 1; }; op_decision' % fake
        return self.sh.run(code)

    def test_mostly_no_sample_is_not_activated(self):
        rc, out = self.decide("verify: REPRODUCED 1, NOT_REPRODUCED 0, NOT_SILENCED 0, NO_SAMPLE 5")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("ACTIVATED", out)
        self.assertIn("HELPER policy-unclassified on", out)               # raw keeps the events
        self.assertNotIn("UNCLASSIFIED_DECISION", out)                    # no environment variable to set
        self.assertEqual(open(os.path.join(self.sh.bundle, "state", "unclassified.applied")).read().split(), ["verified-none", "raw"])

    def test_mostly_reproduced_is_still_activated(self):
        rc, out = self.decide("verify: REPRODUCED 5, NOT_REPRODUCED 0, NOT_SILENCED 0, NO_SAMPLE 1")
        self.assertIn("ACTIVATED", out)


class RawQuestionComesWithThePointOfNoReturnF7(_OneCommand):
    """E7-aio (and the target): with the migrated rules not active the finish stopped once more on the raw-at-finish
    question, after the point of no return. It is asked in the same round, with the choice the environment variable
    gave before (activate-force), and the finish then runs without a stop."""

    def test_both_questions_in_one_stop_and_the_finish_runs(self):
        for m in ALL_RUN.split():
            self.sh.write("state/" + m, "t")
        self.sh.write("state/unclassified.applied", "verified-none\nraw\n")
        self.sh.write("state/ruleset.verify_summary", "verify: REPRODUCED 4, NOT_REPRODUCED 1, NOT_SILENCED 0, NO_SAMPLE 1")
        env = {"MARK_run": ALL_RUN, "MARK_confirm_no_return": "confirm.no_return", "MARK_agents": "phase.agents", "MARK_finish": "phase.finish"}
        rc, out = self.next(env)
        self.assertEqual(rc, 3, out)
        self.assertIn("POINT OF NO RETURN", out)
        self.assertIn('"raw-at-finish"', out)
        self.assertIn('"activate-force"', out)
        self.answer(lambda d: d["point-of-no-return"][0].update(action="confirm"))
        self.answer(lambda d: d["unclassified-finish"][0].update(action="activate-force"))
        rc, out = self.next(env)
        self.assertEqual(rc, 0, out)
        self.assertIn("MIGRATION FINISHED", out)
        self.assertEqual(self.children()[-3:], ["confirm-no-return", "agents", "finish"])

    def test_the_finish_takes_activate_force(self):
        self.sh.write("state/unclassified.applied", "verified-none\nraw\n")
        self.sh.write("decisions.json", {"unclassified-finish": [{"id": "raw-at-finish", "action": "activate-force"}]})
        rc, out = quiet(H.raw_decision, self.dec, os.path.join(self.sh.bundle, "state"), "", "")
        self.assertEqual(rc, 5, out)


class BackOnAClusterMasterGoesBackTheClusterF7(unittest.TestCase):
    """DOC2: './wazuh-migrate.sh back' on a cluster master read the all-in-one bundle ("no migration is recorded");
    the cluster form was long. 'back' (and 'back master') now go to the cluster the one command runs from here."""

    def test_back_and_back_master_reach_the_cluster(self):
        t = tempfile.mkdtemp(prefix="f7-back-")
        self.addCleanup(shutil.rmtree, t, True)
        src = os.path.join(t, "src")
        shutil.copytree(SRC, src, ignore=shutil.ignore_patterns("__pycache__"))
        open(os.path.join(src, "migrate-cluster.sh"), "w").write('echo "CLUSTER $*"\n')
        home = os.path.join(t, "home")
        os.makedirs(home)
        open(os.path.join(home, "inventory.json"), "w").write("{}")
        env = dict(os.environ, CLUSTER_HOME=home, BUNDLE_DIR=os.path.join(t, "bundle"), WORK_DIR=os.path.join(t, "work"))
        for args, want in ((["back"], "back"), (["back", "master"], "back master")):
            p = subprocess.run(["bash", os.path.join(src, "migrate.sh")] + args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = p.stdout.decode()
            self.assertIn("CLUSTER --inventory %s %s" % (os.path.join(home, "inventory.json"), want), out)
            self.assertNotIn("no migration is recorded", out)


class KilledRunsAssistantIsWaitedForF7(unittest.TestCase):
    """E7-aio U5: kill -9 during the 5.0 install left the assistant running (the signal does not reach it); the rerun
    saw a partial install, added -o and started a second assistant beside it, which failed. A rerun now finds the
    assistant still running in its directory, waits for it and starts none."""

    def test_the_rerun_waits_for_the_running_assistant(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        d = os.path.join(sh.tmp, "v5-install")
        os.makedirs(d)
        open(os.path.join(d, "wazuh-install.sh"), "w").write("sleep 4\n")
        other = os.path.join(sh.tmp, "elsewhere")
        os.makedirs(other)
        open(os.path.join(other, "wazuh-install.sh"), "w").write("sleep 30\n")
        code = ('( cd %s && setsid bash ./wazuh-install.sh & ); ( cd %s && setsid bash ./wazuh-install.sh & ); sleep 0.5; '
                't0=$SECONDS; assistant_wait %s; echo "RC=$? waited=$((SECONDS - t0))"; assistant_running %s | wc -l; '
                'pkill -f "elsewhere" || true') % (d, other, d, d)
        rc, out = sh.run(code, env={"MIG_POLL_SECS": "1"}, timeout=60)
        self.assertIn("still running (pid", out.replace("is still running (pid", "still running (pid"))
        self.assertIn("no second one is started", out)
        m = re.search(r"RC=(\d+) waited=(\d+)", out)
        self.assertEqual(m.group(1), "0", out)
        self.assertGreaterEqual(int(m.group(2)), 2, out)                 # it waited for the one in its directory
        self.assertLess(int(m.group(2)), 20, out)                        # not for the one elsewhere
        self.assertEqual(out.strip().splitlines()[-1].strip(), "0", out)

    def test_install5_waits_before_any_partial_check(self):
        txt = open(os.path.join(SRC, "migrate.sh")).read()
        body = txt[txt.index("rp_install5() {"):txt.index("rp_install5_external() {")]
        self.assertLess(body.index("assistant_wait"), body.index("adding -o"))


E2 = helpers.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_e2_fold.py"), "test_e2_fold_f7")


class AnAgentStoppedAtTheFinishIsAWaitF7(E2._Compare):
    """E7-aio U9: an agent stopped before the confirmation made the re-verification FAIL ("agents active on 5.0 LOST",
    exit 1); one stopped after its upgrade request held the command 66 minutes and then failed the agents gate. Now the
    re-verification names it (AWAY), the gate leaves it on 4.x waiting for it, the fleet run stops promptly, and the one
    command ends with exit 4 WAITING naming it."""

    def agents(self):
        self.bundle({})
        a4 = [{"id": "003", "name": "e7aio-lin", "status": "active", "group": ["default"]}]
        E2.write(os.path.join(self.fp, "agents.json"), json.dumps(a4))
        E2.write(os.path.join(self.t4, "agents.json"), json.dumps(a4))
        E2.write(os.path.join(self.t5, "agents.json"), json.dumps([{"id": "003", "name": "e7aio-lin", "status": "disconnected", "group": ["default"]}]))

    def test_a_reverification_names_the_agent_and_does_not_fail(self):
        self.agents()
        r, out = self.compare(env={"HISTORY_PENDING": "0", "VERIFY_AGAIN": "1"})
        line = self.line(out, "agents active on 5.0")
        self.assertIn("AWAY", line)
        self.assertIn("003 e7aio-lin", line)
        self.assertNotIn("LOST", line)
        r, out = self.compare(env={"HISTORY_PENDING": "0"})            # the first verification still calls it LOST
        self.assertIn("LOST", self.line(out, "agents active on 5.0"))

    def test_the_gate_leaves_a_waiting_agent_on_4x_and_passes(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        sh.write("fleet/upgrade-state.json", {"agents": {"002": {"name": "win", "state": "upgraded"},
                                                         "003": {"name": "lin", "state": "waiting-for-agent", "reason": ""}}})
        sh.write("fleet/trust-audit.txt", "002 win v5.0.0 verification_mode=full\n")
        sh.write("preflight/fleet-facts.json", {"agents": {}})
        rc, out = sh.run("ag_gate")
        self.assertEqual(rc, 0, out)
        self.assertIn("agent 003", out)
        self.assertIn("waits for it to connect", out)
        self.assertIn("0 failed or unproven", out)

    def test_the_fleet_run_has_a_short_wait_for_disconnected_agents(self):
        txt = open(os.path.join(SRC, "fleet-upgrade.py")).read()
        self.assertIn('"--leave-disconnected", type=int, default=180', txt)
        self.assertRegex(txt, r'parked = \[i for i in open_left if play\[i\]\["state"\] == "waiting-for-agent"\]')
        self.assertIn('st.get("progress_at", t_start) >= 60', txt)      # a progress line at least every minute (E8-cluster-deb 7)

    def test_the_one_command_says_waiting_with_the_agent(self):
        oc = _OneCommand("setUp")              # the helper only, not a case of its own
        oc.setUp()
        self.addCleanup(oc.sh.close)
        for m in ALL_RUN.split() + ["confirm.no_return", "phase.agents"]:
            oc.sh.write("state/" + m, "t")
        oc.sh.write("state/legacy.open", "keep legacy: 003 (v4.14.11, disconnected)\n")
        rc, out = oc.next()
        self.assertEqual(rc, 4, out)
        self.assertIn("WAITING: agents still on 4.x (003 (v4.14.11, disconnected))", out)
        self.assertIn("upgraded once it connects again", out)


F6 = helpers.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_f6_fold.py"), "test_f6_fold_f7")


class CoveredRuleForcedToMigrateAsTheOneCommandSeesItF7(F6.RmigFollowUpQuestionsItem2):
    """E7-aio (E6 gap 1 on the tree before F6): covered.100500 answered "migrate" opened fields/audit.key in rmig's own
    file only; the step said "done" and the run went on to the settings. F6 carried the question to the flow file; here
    the case as the one command sees it: the ruleset step exits 3 (a question, not a failure) and the QUESTION the
    person reads names fields/audit.key with what its answer needs."""

    def test_the_question_the_person_reads(self):
        sh = self.shell(SRC)
        rc, out = self.first_answers(sh)
        self.assertEqual(rc, 3, out)
        rc, q = quiet(NF.cmd_question, os.path.join(sh.bundle, "decisions.json"))
        self.assertEqual(rc, 0)
        self.assertIn('QUESTION: the 4.x field audit.key (used by rule:100500) has no 5.0 field', q)
        self.assertIn('section "ruleset", "fields/audit.key"', q)
        self.assertIn('"map" with the 5.0 field in "wcs"', q)

    # the parent's cases run in their own module; only the one above here
    test_the_new_question_reaches_the_flow_file_and_the_step_stays_open = None
    test_once_answered_the_rule_is_built = None
    test_a_file_of_the_users_own_gets_the_question = None
    test_without_the_change_the_step_is_done_and_the_rule_left_out = None


CODES = re.compile(r"(\([A-Z][a-z]+, 20\d\d-\d\d-\d\d\)|\(decision \d|\bdecision \d+[a-z]?\)|\(rule \d|\brule \d+[;)]|C4 converter|\bC4:|\bOF1\b|\bK5:|\(R1:)")


def shipped_strings(tree):
    """(file, line, text) of every quoted string a person can see: bash lines that are not comments, and Python lines
    that print, log, refuse or describe an option (docstrings and comments are not messages)."""
    out = []
    for root, _, files in os.walk(tree):
        if "__pycache__" in root or os.path.join("converter", "tests") in root or os.path.join("converter", "evidence") in root:
            continue
        for fn in files:
            p = os.path.join(root, fn)
            if not (fn.endswith(".sh") or fn.endswith(".py")):
                continue
            for n, l in enumerate(open(p, errors="replace"), 1):
                s = l.strip()
                if s.startswith("#") or s.startswith('"""') or (fn.endswith(".py") and not re.search(r"\b(print|log|SystemExit|die|help=|bad|warn|ok)\s*\(|help=", l)):
                    continue
                code = re.sub(r"\s#\s.*$", "", l)
                for q in re.findall(r'"((?:[^"\\]|\\.)*)"', code) + re.findall(r"'((?:[^'\\]|\\.)*)'", code):
                    if CODES.search(q):
                        out.append((os.path.relpath(p, tree), n, q[:120]))
    return out


class NoNamesOrDesignCodesInMessagesF7(unittest.TestCase):
    """E7-aio gap 10: a person's name and a date in the assess WARN, "settings stage (C4 converter)", "decision 3",
    "decision 11", "rule 14", "rule 9" in what the person reads. None is left in the shipped messages."""

    def test_the_tree_has_none(self):
        self.assertEqual(shipped_strings(SRC), [])


class NeverConnectedChoiceInTheDecisionsFileF7(_OneCommand):
    """E7-aio gap 12: closing the legacy ports kept open for never-connected agents needed NEVER_CONNECTED_AT_FINISH=close
    in the environment. The finish writes the choice into the decisions file (pre-filled "keep", never a stop), and an
    answer there is read by the next run."""

    def test_the_entry_is_written_and_read(self):
        for m in ALL_RUN.split() + ["confirm.no_return", "phase.agents"]:
            self.sh.write("state/" + m, "t")
        self.sh.write("state/legacy.open", "keep never-connected: 001 \n")
        rc, out = self.next()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("NEVER_CONNECTED_AT_FINISH", out)
        self.assertIn('section "never-connected", entry "at-finish"', out)
        e = json.load(open(self.dec))["never-connected"][0]
        self.assertEqual(e["action"], "keep")
        self.assertFalse(NF.open_questions(json.load(open(self.dec))))         # never a stop
        self.answer(lambda d: d["never-connected"][0].update(action="close"))
        rc, out = self.sh.run('python3 "$HERE/next_flow.py" answer "$MIGRATION_DECISIONS" never-connected at-finish', env={"MIGRATION_DECISIONS": self.dec})
        self.assertEqual(out.strip(), "close")
        self.assertIn('next_flow.py" answer "$MIGRATION_DECISIONS" never-connected at-finish', open(os.path.join(SRC, "migrate.sh")).read())


CL1 = helpers.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_cl1_cluster.py"), "test_cl1_cluster_f7")


class ClusterOneFileAndNewAttemptF7(unittest.TestCase):
    """E8-cluster-deb items 1 and 2: the settings questions of each manager were in cluster-state/decisions/<node>.json
    and stopped the pre-copy before the ruleset step ran (one more stop for the review); the master's raw-at-finish
    question landed there too. Every node question is now carried into the controller's one decisions file, under
    "nodes" -> "<node>", the settings and ruleset steps ask in the same round, and the messages name that file. After
    going back the cluster starts a new attempt: every node's bundle is kept as <bundle>.attempt-<n>."""

    def setUp(self):
        self.c = CL1.Cluster()
        self.addCleanup(self.c.close)
        self.cdec = os.path.join(self.c.t, "decisions.json")

    def test_node_questions_reach_the_controllers_file_and_both_steps_run(self):
        node = {"settings": {"x": {"action": None, "question": {"option": "remote.queue_size", "asks": "a value 5.0 refuses"}}}}
        rc, out, calls = self.c.run("run", "--only", "precopy", DECISIONS=json.dumps(node), FAIL_PAT="settings-node.sh plan-precopy", FAIL_RC="3")
        self.assertEqual(rc, 3, out[-3000:])
        st = [s for _, s in CL1.Cluster.steps(calls)]
        self.assertTrue(any(s.startswith("ruleset-node.sh precopy") for s in st), st)    # the ruleset ran although settings asked
        d = json.load(open(self.cdec))
        self.assertIn("settings", d["nodes"]["wazuh-1"])
        self.assertIn('section "nodes", "wazuh-1", "settings", "x"', subprocess.run(
            ["python3", os.path.join(SRC, "next_flow.py"), "question", self.cdec], stdout=subprocess.PIPE).stdout.decode())
        self.assertIn('answer the questions listed under QUESTION at the end of this run, in %s' % self.cdec, out)   # F8 wording
        self.assertNotIn("FAIL  settings", out)

    def test_the_answer_goes_back_to_the_node(self):
        json.dump({"nodes": {"wazuh-2": {"settings": {"x": {"action": "omit", "reason": "r"}}}}}, open(self.cdec, "w"))
        out = os.path.join(self.c.t, "pushed.json")
        H.node_carry("to-node", self.cdec, "wazuh-2", os.path.join(self.c.t, "none.json"), out)
        self.assertEqual(json.load(open(out))["settings"]["x"]["action"], "omit")

    def test_a_new_attempt_sets_every_nodes_bundle_aside(self):
        os.makedirs(os.path.join(self.c.t, "st", "state"))
        open(os.path.join(self.c.t, "st", "state", "back.done"), "w").write("t\n")
        rc, out, calls = self.c.run("new-attempt", "2")
        self.assertEqual(rc, 0, out[-2000:])
        moved = [c for c in calls if "wazuh-migration-bundle.attempt-2" in c]
        self.assertEqual(len(moved), len(CL1.Cluster.NODES), calls)
        self.assertTrue(all("sudo" not in c or "sudo -n sh -c" in c for c in moved))


if __name__ == "__main__":
    unittest.main()
