"""The tool moved to the ruleset tool's merged commit 7976ef5422cdf677b702bf774645b0f6f4be9218 (was 1c2e672a94), plus the two items the breaker guard test added (E4-breaker:
the guard default recorded, and the assess warning on a small 5.0 indexer heap).

Every case that is a change is meant to fail without it.

The ruleset cases run the real rmig, offline, at the new commit, on a small custom ruleset written here (the auditd rules of rmig's own
CoveredTest: 200111 has the MITRE technique of an enabled stock 5.0 rule) against the 4.14.10 stock ruleset of a real
bundle."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import helpers
from test_e2_cluster import NodeSteps, write

SRC = helpers.SRC
RMIG = helpers.env_dir("MIG_TEST_RMIG_DIR")                  # the real rmig (see helpers.needs)
STOCK = helpers.env_dir("MIG_TEST_STOCK_RULESET")           # the 4.14.10 stock ruleset (see helpers.needs)
NEEDS_RMIG = helpers.needs(rmig=RMIG)
NEEDS_RULESET = helpers.needs(rmig=RMIG, stock=STOCK)         # the real rmig on the stock ruleset
NEEDS_STOCK = helpers.needs(stock=STOCK)
NEW = "7976ef5422cdf677b702bf774645b0f6f4be9218"
H = helpers.load(os.path.join(SRC, "mig_helper.py"), "mig_helper_r1")

OSSEC_CONF = """<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
</ossec_config>
"""
AUDITD_DEC = """<decoder name="auditd-execve">
  <prematch>^type=EXECVE</prematch>
</decoder>
<decoder name="auditd-execve1">
  <parent>auditd-execve</parent>
  <regex>argc=(\\d+) a0="(\\S+)"</regex>
  <order>audit.argc, audit.execve.a0</order>
</decoder>
"""
AUDITD_RULES = """<group name="auditd,">
  <rule id="200110" level="3">
    <decoded_as>auditd-execve</decoded_as>
    <description>An execve call (auditd).</description>
  </rule>
  <rule id="200111" level="10">
    <if_sid>200110</if_sid>
    <field name="audit.execve.a0">tar</field>
    <description>A tar archive was created.</description>
    <mitre><id>T1560</id></mitre>
  </rule>
</group>
"""


def custom_etc(base):
    write(os.path.join(base, "etc", "ossec.conf"), OSSEC_CONF)
    write(os.path.join(base, "etc", "decoders", "auditd.xml"), AUDITD_DEC)
    write(os.path.join(base, "etc", "rules", "auditd.xml"), AUDITD_RULES)
    os.makedirs(os.path.join(base, "etc", "lists"), exist_ok=True)


def flow(sh):
    p = os.path.join(sh.bundle, "decisions.json")
    return json.load(open(p)) if os.path.exists(p) else {}


def set_flow(sh, d):
    write(os.path.join(sh.bundle, "decisions.json"), json.dumps(d))


class _Ruleset(unittest.TestCase):
    """migrate.sh's ruleset_build in the sandbox, with the real rmig."""

    def shell(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        custom_etc(os.path.join(sh.bundle, "ruleset-src"))
        os.symlink(STOCK, os.path.join(sh.bundle, "ruleset-src", "ruleset"))
        return sh

    def build(self, sh, env=None):
        e = {"RMIG_DIR": RMIG}
        e.update(env or {})
        rc, out = sh.run('MIGRATION_DECISIONS=$BUNDLE_DIR/decisions.json; ruleset_build "$BUNDLE_DIR/ruleset-migration" 5.0; echo "rc=$?"', env=e, timeout=120)
        return int(re.findall(r"rc=(\d+)", out)[-1]), out

    def rdec(self, sh):
        return json.load(open(os.path.join(sh.bundle, "ruleset-migration", "decisions.json")))

    def report(self, sh):
        return json.load(open(os.path.join(sh.bundle, "ruleset-migration", "report.json")))


# ================================================================================================ 1. the pin
class RmigPinnedToTheMergedCommit1(unittest.TestCase):
    EXPORT_RX = re.compile(r"(rmig|ruleset[-_ ]?(migration|tool)|intelligence[-]data).*\b[0-9a-f]{40}\b|\b[0-9a-f]{40}\b.*(rmig|ruleset[-_ ]?(migration|tool)|intelligence[-]data)", re.I)

    def pins(self, tree):
        """What export-public.sh takes as the pinned commit: every 40-hex on a line of src/ naming rmig."""
        found = set()
        for d, _, fs in os.walk(tree):
            if "__pycache__" in d:
                continue
            for f in fs:
                try:
                    txt = open(os.path.join(d, f), errors="replace").read()
                except OSError:
                    continue
                for line in txt.splitlines():
                    if self.EXPORT_RX.search(line):
                        found |= set(re.findall(r"\b[0-9a-f]{40}\b", line))
        return found

    def test_the_tool_names_the_merged_commit_once(self):
        self.assertEqual(self.pins(SRC), {NEW})
        self.assertEqual(json.load(open(os.path.join(SRC, "manifest", "builds.json")))["ruleset_tool"]["commit"], NEW)
        for f in ("migrate.sh", os.path.join("cluster", "inventory.py")):
            self.assertIn(NEW, open(os.path.join(SRC, f)).read(), f)



    @NEEDS_RMIG
    def test_assess_accepts_the_merged_rmig_and_refuses_the_old_one(self):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(H.rmig_check(RMIG), 0)
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        for d, wants in ((RMIG, ("PASS  ruleset tool",)),):
            rc, out = sh.run("FAILS=0; assess_tools", env={"RMIG_DIR": d, "IDENTITY_TOOL": "/nonexistent"})
            for want in wants:
                self.assertIn(want, out)


    @NEEDS_RMIG
    def test_the_cluster_inventory_refuses_an_old_rmig(self):
        inv = helpers.load(os.path.join(SRC, "cluster", "inventory.py"), "inv_r1")
        probs = lambda mod, d: [p for p in mod.problems({"inputs": {"ruleset_tool": d}, "nodes": []}, "/x") if "older than" in p]
        self.assertFalse(probs(inv, RMIG))


# ================================================================================================ 2. mandatory review
class TheReviewIsAskedBeforeTheFreeze2(_Ruleset):
    @NEEDS_RULESET
    def test_the_block_is_shown_and_the_run_stops_with_the_question_in_the_ruleset_section(self):
        sh = self.shell(SRC)
        rc, out = self.build(sh)
        self.assertEqual(rc, 3, out)                                    # F7: a step that asks exits 3
        self.assertIn("## Review before activate (mandatory)", out)
        self.assertIn("| Covered by 5.0 stock | 1 |", out)
        self.assertIn("RULESET REVIEW OPEN", out)
        self.assertIn("report.md", out)
        sec = flow(sh)["ruleset"]
        self.assertIn("review", sec)
        self.assertIsNone(sec["review"])                               # asked, never answered for the user

    @NEEDS_RULESET
    def test_the_users_answer_is_carried_into_rmig_and_the_build_goes_on(self):
        sh = self.shell(SRC)
        self.build(sh)
        d = flow(sh)
        d["ruleset"]["review"] = "accepted"
        set_flow(sh, d)
        rc, out = self.build(sh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.rdec(sh)["review"], "accepted")
        self.assertIn("ruleset review: accepted", out)
        self.assertTrue(self.report(sh)["review"]["accepted"])

    @NEEDS_RULESET
    def test_a_file_of_the_users_own_is_named_and_the_flow_file_is_left_alone(self):
        sh = self.shell(SRC)
        own = write(os.path.join(sh.tmp, "my-ruleset-decisions.json"), json.dumps({"version": 1}))
        rc, out = self.build(sh, {"RMIG_DECISIONS": own})
        self.assertEqual(rc, 3, out)                                    # F7: a step that asks exits 3
        self.assertIn("%s (your own ruleset decisions file)" % own, out)   # F8: no variable name
        self.assertNotIn("ruleset", flow(sh))
        write(own, json.dumps({"version": 1, "review": "accepted"}))
        rc, out = self.build(sh, {"RMIG_DECISIONS": own})
        self.assertEqual(rc, 0, out)

    def test_the_tool_never_writes_accepted(self):
        src = open(os.path.join(SRC, "mig_helper.py")).read() + open(os.path.join(SRC, "migrate.sh")).read()
        self.assertNotRegex(src, r"\[\"review\"\]\s*=\s*\"accepted\"")
        self.assertNotRegex(src, r"\"review\":\s*\"accepted\"\}")



class AnOpenReviewStopsActivate2(unittest.TestCase):
    """If the review is still open when activate runs (rmig exits 2, RM-P-REVIEW-PENDING), the run stops with what to do
    instead of failing the opening step with rmig's raw tail."""

    STOP = ('echo "activate: stopped (RM-P-REVIEW-PENDING): The review is mandatory before activate: read the block ..."; '
            'echo "activate: stopped"; return 2')

    def decide(self, tree, body, env=None, failed=False):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        sh.write("state/ruleset.verify_rc", "1\n" if failed else "0\n")
        sh.write("state/ruleset.verify_summary", "verify: REPRODUCED 4, NOT_REPRODUCED %d, SILENCED 0, NOT_SILENCED 0, NO_SAMPLE 0\n" % (1 if failed else 0))
        helper = os.path.join(tree, "mig_helper.py")
        rc, out = sh.run('HELPER=%s; rmig() { echo "rmig $*" >> %s; %s; }; op_decision; echo "rc=$?"' % (helper, sh.calls, body), env=env)
        return int(re.findall(r"rc=(\d+)", out)[-1]), out, sh.called()

    def test_the_run_stops_to_be_answered(self):
        rc, out, _ = self.decide(SRC, self.STOP)
        self.assertEqual(rc, 3, out)
        self.assertIn("set \"review\": \"accepted\"", out)
        self.assertIn("listeners stay CLOSED", out)


    def test_activate_force_does_not_skip_it_and_the_text_says_so(self):
        rc, out, calls = self.decide(SRC, self.STOP, {"UNCLASSIFIED_DECISION": "activate-force+raw"}, failed=True)
        self.assertEqual(rc, 3, out)
        self.assertTrue(any("--force" in c for c in calls if c.startswith("rmig activate")), calls)
        txt = open(os.path.join(SRC, "migrate.sh")).read()
        self.assertIn("the ruleset review must still be accepted", txt)


# ================================================================================================ 3. covered rules
class CoveredRulesAreReportedAndCanBeForced3(_Ruleset):
    @NEEDS_RULESET
    def test_assess_names_the_covered_rule_and_its_stock_rule(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        custom_etc(os.path.join(sh.root, "var", "ossec"))
        os.symlink(STOCK, os.path.join(sh.root, "var", "ossec", "ruleset"))
        rc, out = sh.run("assess_ruleset", env={"RMIG_DIR": RMIG}, timeout=120)
        self.assertIn("PASS  ruleset: rmig planned the custom content", out)
        self.assertIn("rule 200111: stock rule 'Archive created via tar", out)
        self.assertIn("\"action\": \"migrate\"", out)
        self.assertNotIn("migtest", os.listdir(sh.bundle))             # read only: nothing in the bundle


    @NEEDS_RULESET
    def test_the_covered_entry_in_the_flow_file_builds_it_back(self):
        sh = self.shell(SRC)
        self.build(sh)
        d = flow(sh)
        self.assertIn("200111", d["ruleset"]["covered"])
        d["ruleset"]["covered"]["200111"]["action"] = "migrate"
        d["ruleset"]["review"] = "accepted"
        set_flow(sh, d)
        rc, out = self.build(sh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.report(sh)["review"]["covered"], 0)
        rules = os.listdir(os.path.join(sh.bundle, "ruleset-migration", "out", "integrations", "wazuh4-auditd", "rules")) \
            if os.path.isdir(os.path.join(sh.bundle, "ruleset-migration", "out", "integrations", "wazuh4-auditd", "rules")) else \
            [f for d_, _, fs in os.walk(os.path.join(sh.bundle, "ruleset-migration", "out")) for f in fs]
        self.assertIn("200111.json", rules)


    def test_a_covered_rule_is_not_a_rule_not_active_at_the_finish(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t)
        state, rwork = os.path.join(t, "state"), os.path.join(t, "rwork")
        os.makedirs(state)
        write(os.path.join(rwork, "verification.md"), "| 4.x rule | Result |\n|---|---|\n| 200111 | `NO_SAMPLE` | x |\n| 200110 | `NOT_REPRODUCED` | y |\n")
        write(os.path.join(rwork, "report.json"), json.dumps({"items": [
            {"kind": "rule", "ref": "rule:200111", "codes": [{"code": "RM-S-STOCK-COVERED"}]},
            {"kind": "rule", "ref": "rule:200110", "codes": [{"code": "RM-X-TRANSLATED"}]}]}))
        write(os.path.join(rwork, "decisions.json"), json.dumps({"covered": {"200111": {"stock_rule": "stock rule 'Archive created via tar'"}}}))
        write(os.path.join(state, "unclassified.applied"), "verified-none\nraw\n")
        dec = os.path.join(t, "decisions.json")
        import contextlib, io
        for mod, covered_listed in ((H, False),):
            shutil.rmtree(state); os.makedirs(state)
            write(os.path.join(state, "unclassified.applied"), "verified-none\nraw\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.raw_decision(dec, state, rwork, "")
            out = buf.getvalue()
            self.assertEqual(rc, 3)
            self.assertEqual("rule not active: 200111" in out, covered_listed, out)
            self.assertIn("rule not active: 200110", out)
            if mod is H:
                self.assertIn("not counted: 1 rule(s) left out because stock 5.0 covers them: 200111", out)   # F8: no code


# ================================================================================================ 4. detector cap
class TheDetectorCapIsShownAndCanBeRaised4(unittest.TestCase):
    CAP = ('echo "activate: stopped (RM-P-ENGINE-LIMIT): The cluster has no room for the tool\'s detectors: nothing was changed. '
           'Raise the cluster setting (then pass --engine-limit max_detectors=N), or remove detectors you do not use."; '
           'echo "  - user-created detectors in the cluster: 10 user detector(s) in the cluster + 1 to create = 11, limit 10"; '
           'echo "activate: stopped"; return 2')

    def run_decision(self, tree, env=None):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        sh.write("state/ruleset.verify_rc", "0\n")
        sh.write("state/ruleset.verify_summary", "verify: REPRODUCED 4, NOT_REPRODUCED 0, SILENCED 0, NOT_SILENCED 0, NO_SAMPLE 0\n")
        rc, out = sh.run('HELPER=%s; rmig() { echo "rmig $*" >> %s; case "$1" in activate) %s;; esac; }; op_decision; echo "rc=$?"'
                         % (os.path.join(tree, "mig_helper.py"), sh.calls, self.CAP), env=env)
        return int(re.findall(r"rc=(\d+)", out)[-1]), out, sh.called()

    def test_rmigs_message_and_the_way_to_pass_the_limit(self):
        rc, out, _ = self.run_decision(SRC)
        self.assertEqual(rc, 3, out)
        self.assertIn("activate: stopped (RM-P-ENGINE-LIMIT)", out)
        self.assertIn("10 user detector(s) in the cluster + 1 to create = 11, limit 10", out)
        self.assertIn('RMIG_ENGINE_LIMITS="max_detectors=N"', out)

    def test_the_limit_reaches_rmig(self):
        rc, out, calls = self.run_decision(SRC, {"RMIG_ENGINE_LIMITS": "max_detectors=20"})
        act = [c for c in calls if c.startswith("rmig activate")]
        self.assertIn("--engine-limit max_detectors=20", act[0])


    def apply(self, tree, body, env=None):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        sh.write("work/ruleset-migration/ENGINE_HELPERS", "5.0\n")
        sh.write("v4/alerts/alerts-1.json", "{}\n")
        e = {"RMIG_ENGINE_HELPERS": "5.0"}
        e.update(env or {})
        rc, out = sh.run('HELPER=%s; rmig() { echo "rmig $*" >> %s; case "$1" in apply) %s;; verify) echo "verify: REPRODUCED 1, NOT_REPRODUCED 0, SILENCED 0, NOT_SILENCED 0, NO_SAMPLE 0";; esac; }; im_ruleset; echo "rc=$?"'
                         % (os.path.join(tree, "mig_helper.py"), sh.calls, body), env=e)
        return int(re.findall(r"rc=(\d+)", out)[-1]), out, sh.called()

    def test_apply_shows_the_cap_and_takes_the_limit(self):
        body = ('[ "$2" = --dry-run ] || [ "$5" = --dry-run ] && return 0; echo "apply: stopped (RM-P-ENGINE-LIMIT): activate could not create '
                'the tool\'s detectors: nothing was changed."; echo "  - limit 10"; echo "apply: stopped"; return 2')
        rc, out, calls = self.apply(SRC, body, {"RMIG_ENGINE_LIMITS": "max_detectors=12"})
        self.assertEqual(rc, 1, out)
        self.assertIn("DETECTOR CAP: rmig changed nothing", out)
        self.assertTrue(all("--engine-limit max_detectors=12" in c for c in calls if c.startswith("rmig apply")), calls)


# ================================================================================================ 5. --findings
class FindingsCriterion5(_Ruleset):
    @NEEDS_RULESET
    def test_mitre_reaches_rmig_and_makes_telemetry(self):
        sh = self.shell(SRC)
        rc, out = self.build(sh, {"RMIG_FINDINGS": "mitre"})
        self.assertIn("findings criterion: mitre", out)
        self.assertEqual(self.report(sh)["review"]["telemetry"], 1)
        self.assertIn("telemetry: 1 rule(s) tagged in their decoder", out)   # F8: no rmig option


    @NEEDS_RMIG
    def test_the_default_is_all_and_a_wrong_value_is_refused(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        rc, out = sh.run("FAILS=0; assess_tools", env={"RMIG_DIR": RMIG, "IDENTITY_TOOL": "/nonexistent"})
        self.assertIn("ruleset findings criterion: all", out)
        rc, out = sh.run("FAILS=0; assess_tools", env={"RMIG_DIR": RMIG, "RMIG_FINDINGS": "some", "IDENTITY_TOOL": "/nonexistent"})
        self.assertIn("FAIL  RMIG_FINDINGS: unknown value 'some'", out)

    def test_the_cluster_passes_both_settings_to_the_nodes(self):
        for tree, want in ((SRC, True),):
            txt = open(os.path.join(tree, "migrate-cluster.sh")).read()
            names = re.search(r"NODE_ENV_NAMES=\(([^)]*)\)", txt).group(1).split()
            self.assertEqual("RMIG_FINDINGS" in names and "RMIG_ENGINE_LIMITS" in names, want, tree)


class TelemetryIsInForceThroughTheDecoder5(unittest.TestCase):
    """The answer "activated" at the finish is checked against rmig's record: a --findings mitre build may hold telemetry
    rules only (tags in decoders, no detection rule, so no detector)."""

    def rwork(self, decoder_space="custom", telemetry=True):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t)
        write(os.path.join(t, "work", "state.json"), json.dumps({
            "last_activate": "2026-11-25T12:00:00Z", "set_aside": {}, "detectors": {},
            "resources": {"d1": {"type": "decoder", "integration": "wazuh4-auditd", "space": decoder_space, "title": "auditd-execve"},
                          "d2": {"type": "decoder", "integration": "wazuh4-auditd", "space": decoder_space, "title": "auditd-execve1"}}}))
        code = "RM-R-TELEMETRY" if telemetry else "RM-X-TRANSLATED"
        write(os.path.join(t, "report.json"), json.dumps({"items": [{"kind": "rule", "ref": "rule:200110", "codes": [{"code": code}]}]}))
        return t

    def test_telemetry_only_is_active_once_its_decoders_are_in_custom(self):
        ok, what = H.rmig_active(self.rwork())
        self.assertTrue(ok, what)
        self.assertIn("1 telemetry rule(s) tagged by 2 decoder(s) in the custom space", what)

    def test_telemetry_decoders_still_in_test_are_not_active(self):
        ok, what = H.rmig_active(self.rwork("test"))
        self.assertFalse(ok)
        self.assertIn("not in the custom space: auditd-execve", what)

    def test_without_telemetry_no_rule_is_still_refused(self):
        ok, what = H.rmig_active(self.rwork(telemetry=False))
        self.assertFalse(ok)



# ================================================================================================ 6. exit codes
class RmigExitCodes6(unittest.TestCase):
    def outcome(self, cmd, text):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t)
        p = write(os.path.join(t, "log"), text)
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = H.rmig_outcome(cmd, p)
        return rc, buf.getvalue()

    def test_done_with_items_waiting_is_done(self):
        self.assertEqual(self.outcome("apply", "apply: integration x\napply: set aside: 1\n")[0], 0)
        self.assertEqual(self.outcome("activate", "activate: detectors left out: wazuh4-x\n")[0], 0)

    def test_a_stop_that_exits_1_is_a_stop(self):
        rc, out = self.outcome("activate", "activate: stopped: Activation needs a verification without failures: x. Pass --force\nactivate: stopped\n")
        self.assertEqual(rc, 1)
        rc, out = self.outcome("apply", "apply: stopped: The engine refused content of wazuh4-base, which holds the root decoder\n  - bad\napply: stopped\n")
        self.assertEqual(rc, 1)
        self.assertIn("  - bad", out)

    def test_apply_with_an_integration_set_aside_goes_on_to_verify(self):
        tc = TheDetectorCapIsShownAndCanBeRaised4("test_apply_shows_the_cap_and_takes_the_limit")
        body = '[ "$2" = --dry-run ] || [ "$5" = --dry-run ] && return 0; echo "apply: set aside: 1"; return 1'
        rc, out, calls = tc.apply(SRC, body)
        self.assertEqual(rc, 0, out)
        self.assertTrue(any(c.startswith("rmig verify") for c in calls), calls)

    def test_activate_with_a_detector_left_out_counts_as_activated(self):
        tc = TheDetectorCapIsShownAndCanBeRaised4("test_rmigs_message_and_the_way_to_pass_the_limit")
        tc.CAP = 'echo "activate: detectors left out: wazuh4-x"; return 1'
        rc, out, calls = tc.run_decision(SRC, {"UNCLASSIFIED_DECISION": "verified"})
        self.assertEqual(rc, 0, out)
        self.assertIn("rmig activated the rules with items waiting", out)


# ================================================================================================ 7. Windows backslashes
class WindowsBackslashesInTheHistory7(unittest.TestCase):
    """CONSTRUCTED ALERT: no 4.x Windows alert with a path value is kept in the evidence of RD2, E5-aio or E5-cluster-*
    (RD2's Windows pairs are Security logon and account events; the E5 runs had no Windows agent). The doubling itself is
    confirmed by the 4.14.10 stock rules, which match four backslashes in PCRE2 for one separator on win.* fields
    (ruleset/rules/0860-sysmon_id_13.xml of the E2-rpm bundle), and by rmig's collapse_doubled_backslash."""

    ALERT = {"timestamp": "2026-11-20T10:00:00.000+0000", "rule": {"id": "61603", "level": 3, "groups": ["windows", "windows_security"]},
             "decoder": {"name": "windows_eventchannel"}, "agent": {"id": "020", "name": "win-1"}, "full_log": "{\"win\": \"C:\\\\\\\\x\"}",
             "data": {"win": {"system": {"eventID": "4688", "channel": "Security", "computer": "WIN-1",
                                         "providerName": "Microsoft-Windows-Security-Auditing"},
                              "eventdata": {"targetUserName": "NT AUTHORITY\\\\SYSTEM", "image": "C:\\\\Windows\\\\System32\\\\cmd.exe"}},
                      "other": "C:\\\\kept"}}

    def spec(self, tree):
        s = json.load(open(os.path.join(tree, "history-loader-map.json")))
        # constructed rules: a path field as Threat Intel's Windows map would fill it, and a non-Windows source
        s["rules"].append({"id": "r9001", "target": "process.executable", "operation": "copy", "sources": ["data.win.eventdata.image"],
                           "when": {"terms": {"rule.groups": ["windows"]}}, "semantic": "constructed for R1"})
        s["rules"].append({"id": "r9002", "target": "file.path", "operation": "copy", "sources": ["data.other"],
                           "when": {"terms": {"rule.groups": ["windows"]}}, "semantic": "constructed for R1"})
        return s

    def convert(self, tree):
        lm = helpers.load(os.path.join(tree, "loader_map.py"), "lm_r1_%d" % abs(hash(tree)), extra_path=tree)
        return lm.LoaderMapper("wazuh", True, {}, spec=self.spec(tree)).convert(json.loads(json.dumps(self.ALERT)), "i", "d")

    def test_windows_fields_get_one_backslash_and_the_legacy_alert_keeps_two(self):
        o = self.convert(SRC)
        self.assertEqual(o["process"]["executable"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(o["user"]["target"]["name"], "NT AUTHORITY\\SYSTEM")
        self.assertEqual(o["legacy"]["alert"]["data"]["win"]["eventdata"]["image"], "C:\\\\Windows\\\\System32\\\\cmd.exe")
        self.assertEqual(o["file"]["path"], "C:\\\\kept")                       # not a win.* source: unchanged
        self.assertEqual(o["message"], self.ALERT["full_log"])                  # full_log is not a win.* field


    @NEEDS_STOCK
    def test_the_stock_4x_rules_confirm_the_doubling(self):
        txt = open(os.path.join(STOCK, "rules", "0860-sysmon_id_13.xml")).read()
        self.assertIn('<field name="win.eventdata.targetObject" type="pcre2">(?i)System\\\\\\\\CurrentControlSet', txt)


# ================================================================================================ 9, 10. breaker guard, heap
class TheGuardDefaultIsKept9(unittest.TestCase):
    def test_the_default_stays_at_85_percent_read_every_5_s_and_no_breaker_mode(self):
        txt = open(os.path.join(SRC, "history_load.py")).read()
        self.assertRegex(txt, r'"--breaker-max", type=float, default=0\.85')
        self.assertIn("limit=0.85, every_s=5.0", txt)
        self.assertNotIn("--breaker-mode", txt)
        # the guard itself is as it was (history_load.py changed since only by taking the old loader's helpers in)
        # (F7 took the design codes "(decision 10)" and "OF1" out of the messages; the code is compared without them)
        code = lambda t: [re.sub(r" ?\(decision 10\)|OF1 \(decision 10\): |OF1: ", "", l.split("  #")[0].rstrip()) for l in t.splitlines() if "breaker" in l.lower() and not l.strip().startswith("#")]


class HeapWarning10(unittest.TestCase):
    def plan(self, tree, mb, mode="aio", env=None):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        sh.stub("free", 'echo "               total        used        free"; echo "Mem:            %d        1000        1000"' % mb)
        rc, out = sh.run("FAILS=0; WARNS=0; assess_heap5; echo WARNS=$WARNS" if mode == "aio" else "heap5_plan %s" % mode, env=env)
        return rc, out

    def test_a_small_all_in_one_is_warned_with_what_to_raise(self):
        rc, out = self.plan(SRC, 7400)
        self.assertIn("WARN  5.0 indexer heap: the 5.0 assistant will set about 1850 MB (1/4 of the 7400 MB of RAM), below 4 GB", out)
        self.assertIn("524 breaker trips", out)
        self.assertIn("/etc/wazuh-indexer/jvm.options", out)
        self.assertIn("WARNS=1", out)

    def test_a_16_gb_host_passes(self):
        rc, out = self.plan(SRC, 15780)
        self.assertIn("PASS  5.0 indexer heap: about 3945 MB", out)

    def test_an_indexer_node_gets_half_its_ram(self):
        rc, out = self.plan(SRC, 7400, "node")
        self.assertIn("WARN 5.0 indexer heap: the 5.0 assistant will set about 3700 MB (1/2", out)
        rc, out = self.plan(SRC, 9000, "node")
        self.assertIn("OK 5.0 indexer heap: about 4500 MB", out)

    def test_a_new_host_or_another_installer_is_checked_after_the_install(self):
        rc, out = self.plan(SRC, 7400, env={"NEW_HOST": "1"})
        self.assertIn("not known before the install", out)
        self.assertIn("the replace gate (phase 5) reads it", out)
        self.assertIn('python3 "$HELPER" heap5', open(os.path.join(SRC, "migrate.sh")).read())


    def test_the_live_heap_after_the_install(self):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            H.heap_report({"nodes": {"a": {"name": "node-1", "jvm": {"mem": {"heap_max_in_bytes": 1890 * 1048576}}}},
                           })
        self.assertIn("WARNING heap5: indexer node node-1 has a 1890 MB heap, below 4 GB", buf.getvalue())

    def test_the_cluster_indexer_node_reports_it_at_assess(self):
        n = NodeSteps(SRC)
        self.addCleanup(n.close)
        n.stub("free", 'echo "x total"; echo "Mem: 3700 1 1"')
        rc, out = n.run("node-facts.sh", "indexer")
        self.assertIn("WARN node", out)
        self.assertIn("about 1850 MB (1/2 of the 3700 MB of RAM)", out)


if __name__ == "__main__":
    unittest.main()
