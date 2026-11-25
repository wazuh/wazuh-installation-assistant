"""OF1: offline fixes to the merged tool after the end-to-end runs and the design decisions of 2026-11-24."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

import helpers

SRC = helpers.SRC
MIGRATE = os.path.join(SRC, 'migrate.sh')

IS = helpers.load(os.path.join(SRC, "identity_stage.py"), "of1_identity_stage")


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


def write(p, content):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb" if isinstance(content, bytes) else "w") as f:
        f.write(content)
    return p


# ------------------------------------------------------------------------------------------------ 1. E2-deb G2
class IdentityRestartThroughTheUnitG2(unittest.TestCase):
    """The identity stage restarts the manager with systemctl, so its daemons live in wazuh-manager.service."""

    def restart(self, mod, env):
        t = tempfile.mkdtemp()
        try:
            b = os.path.join(t, "bin")
            os.makedirs(b)
            write(os.path.join(b, "systemctl"), "#!/bin/sh\nexit 0\n")
            os.chmod(os.path.join(b, "systemctl"), 0o755)
            ran = []

            def fake_run(cmd, **k):
                ran.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0, "", "")

            def up(*a, **k):
                raise urllib.error.HTTPError("https://localhost:55000/", 401, "unauthorized", {}, None)
            e = dict(os.environ, PATH=b + ":" + os.environ["PATH"], **env)
            with mock.patch.dict(os.environ, e, clear=True), mock.patch.object(mod.subprocess, "run", fake_run), \
                    mock.patch.object(mod.urllib.request, "urlopen", up), mock.patch.object(mod, "log", lambda m: None):
                st = mod.State(os.path.join(t, "st"))
                mod.restart_manager(st, "test")
            return ran
        finally:
            shutil.rmtree(t, ignore_errors=True)

    def test_the_stage_restarts_through_the_unit(self):
        ran = self.restart(IS, {"MIG_ASSUME_SYSTEMD": "1"})
        self.assertEqual(ran[0][1:], ["restart", "wazuh-manager"], ran)
        self.assertTrue(ran[0][0].endswith("systemctl"), ran)


    def test_without_systemd_the_control_script_stays(self):
        with mock.patch.object(IS.shutil, "which", lambda n: None):
            self.assertEqual(IS.restart_cmd(), [IS.CONTROL, "restart"])


# ------------------------------------------------------------------------------------------------ 2. E2-deb G4
class PerAgentDatabasesG4(unittest.TestCase):
    """Going back restores queue/db/NNN.db (inventory, FIM baselines, SCA state), not only global.db."""

    def setUp(self):
        self.sh = helpers.Shell(MIGRATE)
        r = self.sh.root
        for n, data in (("global.db", "G"), ("000.db", "0" * 10), ("001.db", "1" * 2000), ("002.db", "2" * 300), ("002.db-wal", "w" * 7)):
            self.sh.write("var/ossec/queue/db/" + n, data, base=r)
        self.sh.write("var/ossec/etc/ossec.conf", "<ossec_config/>", base=r)
        self.tar = self.sh.write("install-files.tar", "x", base=self.sh.tmp)

    def tearDown(self):
        self.sh.close()

    def freeze(self):
        return self.sh.run('pc_ruleset_src() { :; }; pc_ruleset_build() { :; }; fz_raw_copy',
                           env={"V4_INSTALL_FILES_TAR": self.tar})

    def members(self):
        import tarfile
        with tarfile.open(os.path.join(self.sh.bundle, "v4/rollback/var-ossec.tar.gz")) as t:
            return sorted(os.path.basename(m.name) for m in t if "/queue/db/" in "/" + m.name)

    def test_the_freeze_archives_and_lists_every_per_agent_database(self):
        rc, out = self.freeze()
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.members(), ["000.db", "001.db", "002.db", "002.db-wal", "global.db"], out)
        listed = open(os.path.join(self.sh.bundle, "v4/rollback/agent-dbs.txt")).read().split()
        self.assertEqual(listed, ["000.db", "10", "001.db", "2000", "002.db", "300", "002.db-wal", "7"])
        self.assertIn("per-agent databases in the rollback archive: 4 of 4", out)


    def test_verify_bundle_refuses_an_archive_missing_one(self):
        self.freeze()
        with open(os.path.join(self.sh.bundle, "v4/rollback/agent-dbs.txt"), "a") as f:
            f.write("003.db 99\n")
        rc, out = self.sh.run('agent_dbs_check "$BUNDLE_DIR/v4/rollback/var-ossec.tar.gz" "$BUNDLE_DIR/v4/rollback/agent-dbs.txt"')
        self.assertNotEqual(rc, 0, out)
        self.assertIn("003.db", out)

    def test_going_back_restores_them_and_drops_the_reinstall_leftovers(self):
        self.freeze()
        db = os.path.join(self.sh.root, "var/ossec/queue/db")
        shutil.rmtree(db)
        write(os.path.join(db, "global.db"), "fresh")              # what the 4.x reinstall wrote
        write(os.path.join(db, "001.db-wal"), "stale")             # would be replayed into the restored 001.db
        rc, out = self.sh.run('R=$BUNDLE_DIR/v4/rollback; bk_agent_dbs_prepare $R; tar -xzf $R/var-ossec.tar.gz -C /; bk_agent_dbs_check $R')
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(os.path.join(db, "001.db-wal")), out)
        self.assertEqual(os.path.getsize(os.path.join(db, "001.db")), 2000)
        self.assertIn("per-agent databases restored: 4 file(s)", out)

    def test_bk_restore_calls_them_around_the_extraction(self):
        rc, out = self.sh.run("type bk_restore")
        i, j, k = out.index("bk_agent_dbs_prepare"), out.index('tar -xzf "$R/var-ossec.tar.gz"'), out.index("bk_agent_dbs_check")
        self.assertLess(i, j)
        self.assertLess(j, k)

    def test_an_older_bundle_without_the_list_still_goes_back(self):
        rc, out = self.sh.run('mkdir -p $BUNDLE_DIR/r; bk_agent_dbs_check $BUNDLE_DIR/r')
        self.assertEqual(rc, 0, out)
        self.assertIn("holds no per-agent databases", out)


# ------------------------------------------------------------------------------------------------ 3. E2-deb G5
SS = helpers.load(os.path.join(SRC, "settings_stage.py"), "of1_settings_stage")


class StockReferenceOnDebG5(unittest.TestCase):
    """On deb the 4.x postinst deletes packages_files: the shipped reference is the deb path on purpose, and said."""

    def stock(self, script, fam, gen, osr='ID=ubuntu\nVERSION_ID="24.04"\n'):
        sh = helpers.Shell(script)
        try:
            o = sh.write("os-release", osr, base=sh.tmp)
            if gen:
                g = sh.write("var/ossec/packages_files/manager_installation_scripts/gen_ossec.sh",
                             'echo "<ossec_config><generated_on_host/></ossec_config>"\n', base=sh.root)
            rc, out = sh.run('PKGFAM=%s; settings_stock "$BUNDLE_DIR/stock"; cat "$BUNDLE_DIR/stock/SOURCE"; '
                             'grep -c generated_on_host "$BUNDLE_DIR/stock/ossec.conf"' % fam, env={"MIG_OS_RELEASE": o})
            return rc, out
        finally:
            sh.close()

    def test_deb_uses_the_shipped_reference_on_purpose_and_says_so(self):
        rc, out = self.stock(MIGRATE, "deb", gen=False)
        self.assertIn("deb host", out)
        self.assertIn("used on purpose", out)
        self.assertIn("stock-4.14.10-ubuntu24 (made for this distribution and release", out)

    def test_deb_never_runs_a_generator_even_if_one_were_left(self):
        rc, out = self.stock(MIGRATE, "deb", gen=True)
        self.assertTrue(out.rstrip().endswith("0"), out)

    def test_another_distribution_is_named(self):
        rc, out = self.stock(MIGRATE, "deb", gen=False, osr='ID=debian\nVERSION_ID="12"\n')
        self.assertIn("made for another distribution: none ships for debian 12", out)

    def test_rpm_keeps_generating_on_the_host(self):
        rc, out = self.stock(MIGRATE, "rpm", gen=True)
        self.assertIn("generated on this host", out)
        self.assertTrue(out.rstrip().endswith("1"), out)


    def test_the_settings_report_repeats_it(self):
        t = tempfile.mkdtemp()
        try:
            write(os.path.join(t, "stock", "SOURCE"), "stock reference: deb host: X\n")
            write(os.path.join(t, "out", "report.md"), "# Migration report\n")
            quiet(SS.stock_note, os.path.join(t, "stock"), os.path.join(t, "out"))
            self.assertIn("## Stock 4.x reference\n\nstock reference: deb host: X", open(os.path.join(t, "out", "report.md")).read())
        finally:
            shutil.rmtree(t, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ 4. E2-deb G6
FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "settings")
STOCK = os.path.join(SRC, "converter", "refs", "stock-4.14.10-ubuntu24")
BASE = os.path.join(SRC, "converter", "refs", "base-5.0.0-aio")
DAY_WAIT = "local_internal_options.conf:/line[21]/monitord.day_wait"


class DecisionsCarryTheirQuestionG6(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="of1-settings-")
        self.v4 = os.path.join(self.t, "v4")
        shutil.copytree(os.path.join(FX, "e1x-aio"), self.v4)
        self.answers = json.load(open(os.path.join(self.v4, "decisions.json")))
        os.unlink(os.path.join(self.v4, "decisions.json"))
        self.dec = os.path.join(self.t, "decisions.json")
        del SS.REFUSED[:]

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def plan(self, mod):
        return quiet(mod.main, ["plan", "--v4", self.v4, "--stock", STOCK, "--base", BASE, "--decisions", self.dec,
                                "--work", os.path.join(self.t, "work")])

    def test_an_open_entry_carries_what_is_asked_the_range_and_each_answer(self):
        rc, out = self.plan(SS)
        self.assertEqual(rc, 3, out)
        q = json.load(open(self.dec))["settings"][DAY_WAIT]["question"]
        self.assertIn("would stop", q["asks"])
        self.assertEqual(q["allowed"], "an integer from 1 to 600 (the 5.0 build's range table)")
        self.assertEqual(sorted(q["answers"]), ["keep", "omit", "replace"])
        self.assertIn("open: settings / %s: Read by" % DAY_WAIT, out)


    def answer_keep(self):
        a = dict(self.answers)
        a[DAY_WAIT] = {"action": "keep", "reason": "we want 4.x's value"}      # 4.x's value is out of 5.0's range
        json.dump({"settings": a}, open(self.dec, "w"))

    def test_a_refused_answer_says_why_points_at_the_entry_and_reopens_it(self):
        self.answer_keep()
        rc, out = self.plan(SS)
        self.assertEqual(rc, 3, out)
        self.assertIn("REFUSED ANSWER in %s: settings / %s: the converter refused this answer: Decision value does not satisfy" % (self.dec, DAY_WAIT), out)
        e = json.load(open(self.dec))["settings"][DAY_WAIT]
        self.assertIsNone(e["action"])
        self.assertEqual(e["refused"]["answer"]["action"], "keep")
        self.assertIn("range", e["question"]["asks"])
        others = [k for k in self.answers if k != DAY_WAIT]
        self.assertTrue(all(json.load(open(self.dec))["settings"][k]["action"] for k in others))   # the other answers stand


    def test_an_answer_without_a_reason_is_refused_by_name(self):
        a = dict(self.answers)
        a[DAY_WAIT] = {"action": "replace", "value": "10", "reason": " "}
        json.dump({"settings": a}, open(self.dec, "w"))
        rc, out = self.plan(SS)
        self.assertEqual(rc, 3, out)
        self.assertIn("settings / %s: every answer needs a non-empty" % DAY_WAIT, out)


# ------------------------------------------------------------------------------------------------ 5. E2-deb G7
class PhaseNineBannerG7(unittest.TestCase):
    def setUp(self):
        self.sh = helpers.Shell(MIGRATE)

    def tearDown(self):
        self.sh.close()

    def test_the_banner_says_the_history_is_pending_and_the_bundle_is_kept(self):
        self.sh.write("state/phase.verify", "x")
        rc, out = self.sh.run("banner_phase9", env={"HISTORY_LOAD": "after-open"})
        self.assertIn("THE 4.x HISTORY IS STILL PENDING (it has not started)", out)
        self.assertIn("'finish' waits for the history", out)
        self.assertIn("the bundle, the only copy of the 4.x alerts once 4.x is gone, is kept until the history is proven", out)
        self.assertIn("after the confirmation going back is refused", out)

    def test_once_the_history_is_on_the_banner_does_not_mention_it(self):
        self.sh.write("state/history.on", "x")
        rc, out = self.sh.run("banner_phase9", env={"HISTORY_LOAD": "after-open"})
        self.assertNotIn("PENDING", out)

    def test_confirming_with_the_history_pending_says_it_too(self):
        self.sh.write("state/phase.verify", "x")
        self.sh.write("state/T_history_load_begin", "2026-11-24T10:00:00Z\n")
        rc, out = self.sh.run("cmd_confirm", env={"HISTORY_LOAD": "after-open"})
        self.assertEqual(rc, 0, out)
        self.assertIn("its load started at 2026-11-24T10:00:00Z and has not finished", out)


    def test_going_back_is_refused_after_the_point_of_no_return(self):
        """Decision 11: no test covered it before OF1 (the refusal itself existed: cmd_back)."""
        for m in ("replace.remove4x", "confirm.no_return"):
            self.sh.write("state/" + m, "2026-11-24T10:00:00Z\n")
        rc, out = self.sh.run("cmd_back; echo reached")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("the point of no return was confirmed at 2026-11-24T10:00:00Z: going back is not offered", out)
        self.assertNotIn("reached", out)
        self.assertNotIn("GOING BACK", out)


# ------------------------------------------------------------------------------------------------ 6. E2-deb G9
H = helpers.load(os.path.join(SRC, "mig_helper.py"), "of1_mig_helper")


class DefaultGroupPassWithNeverConnectedG9(unittest.TestCase):
    AGENTS = [{"id": "000", "group": []}, {"id": "001", "status": "never_connected", "group": ["default"]},
              {"id": "002", "version": "Wazuh v5.0.0", "status": "active", "group": ["default", "acme-linux"]}]

    def groups(self, mod_ss, mod_h):
        t = tempfile.mkdtemp(prefix="of1-groups-")
        try:
            g = os.path.join(t, "groups4")
            shutil.copytree(os.path.join(FX, "groups"), g)
            v = json.dumps(mod_h.group_versions_of(self.AGENTS))
            rc, out = quiet(mod_ss.main, ["groups", "--phase", "post-upgrade", "--groups", g, "--decisions", os.path.join(t, "d.json"),
                                          "--work", os.path.join(t, "w"), "--shared", os.path.join(t, "shared"), "--versions", v, "--dry-run"])
            return rc, out, json.loads(out.strip().splitlines()[-1])
        finally:
            shutil.rmtree(t, ignore_errors=True)

    def test_default_gets_its_pass_when_only_never_connected_agents_are_below_5(self):
        rc, out, res = self.groups(SS, H)
        self.assertIn("default", [x["group"] for x in res["applied"]], out)
        self.assertNotIn("default", res["left"])
        self.assertIn("never-connected agent(s) ['001'] do not hold the post-upgrade pass back", out)


    def test_an_agent_that_reported_4x_still_holds_the_group(self):
        self.AGENTS = self.AGENTS + [{"id": "003", "version": "Wazuh v4.14.10", "status": "disconnected", "group": ["default"]}]
        rc, out, res = self.groups(SS, H)
        self.assertIn("default", res["left"], out)

    def test_the_api_query_asks_for_the_status(self):
        self.assertIn("select=id,version,group,status", open(os.path.join(SRC, "mig_helper.py")).read())


# ------------------------------------------------------------------------------------------------ 7. decision 3
class UnclassifiedDefaultDecision3(unittest.TestCase):
    """Default answer: activate the rules that verified, raw indexing on until the finish; no stop to ask."""

    def decide(self, script, vrc, summary, decision=None):
        sh = helpers.Shell(script)
        try:
            sh.write("state/ruleset.verify_rc", "%s\n" % vrc)
            sh.write("state/ruleset.verify_summary", summary + "\n")
            helper = sh.write("helper.py", "import sys\nopen(%r, 'a').write('helper ' + ' '.join(sys.argv[1:]) + '\\n')\n" % sh.calls, base=sh.tmp)
            env = {"UNCLASSIFIED_DECISION": decision} if decision is not None else {}
            rc, out = sh.run('HELPER=%s; rmig() { echo "rmig $*" >> %s; }; op_decision' % (helper, sh.calls), env=env)
            try:
                applied = open(os.path.join(sh.bundle, "state/unclassified.applied")).read().split()
            except OSError:
                applied = None
            return rc, out, sh.called(), applied
        finally:
            sh.close()

    FAILED = "verify: REPRODUCED 4, NOT_REPRODUCED 1, SILENCED 0, NOT_SILENCED 0, NO_SAMPLE 1"
    NO_FAIL = "verify: REPRODUCED 4, NOT_REPRODUCED 0, SILENCED 0, NOT_SILENCED 0, NO_SAMPLE 1"
    CLEAN = "verify: REPRODUCED 4, NOT_REPRODUCED 0, SILENCED 0, NOT_SILENCED 0, NO_SAMPLE 0"

    def test_failed_rules_by_default_open_with_raw_on_and_no_rule_forced(self):
        rc, out, calls, applied = self.decide(MIGRATE, 1, self.FAILED)
        self.assertEqual(rc, 0, out)
        self.assertEqual(applied, ["verified-none", "raw"])
        self.assertIn("helper policy-unclassified on", calls)
        self.assertFalse([c for c in calls if c.startswith("rmig activate")], calls)
        self.assertIn("the default answer applies, verified+raw", out)


    def test_no_failure_but_rules_without_sample_are_activated_without_force(self):
        rc, out, calls, applied = self.decide(MIGRATE, 0, self.NO_FAIL)
        self.assertEqual(applied, ["activate", "raw"], out)
        act = [c for c in calls if c.startswith("rmig activate")]
        self.assertEqual(len(act), 1, calls)
        self.assertNotIn("--force", act[0])

    def test_clean_rules_by_default_also_switch_raw_on_until_the_finish(self):
        rc, out, calls, applied = self.decide(MIGRATE, 0, self.CLEAN)
        self.assertEqual(applied, ["activate", "raw"], out)

    def test_an_explicit_answer_still_wins(self):
        rc, out, calls, applied = self.decide(MIGRATE, 1, self.FAILED, "accept")
        self.assertEqual(applied, ["accept"], out)
        self.assertNotIn("helper policy-unclassified on", calls)
        rc, out, calls, applied = self.decide(MIGRATE, 1, self.FAILED, "activate-force+raw")
        self.assertEqual(applied, ["activate-force", "raw"], out)
        self.assertTrue(any("--force" in c for c in calls), calls)

    def test_ask_keeps_the_old_stop(self):
        rc, out, calls, applied = self.decide(MIGRATE, 1, self.FAILED, "ask")
        self.assertEqual(rc, 3, out)
        self.assertIn("listeners stay CLOSED", out)

    def test_the_finish_switches_the_default_raw_off(self):
        sh = helpers.Shell(MIGRATE)
        try:
            sh.write("state/unclassified.applied", "verified-none\nraw\n")
            helper = sh.write("helper.py", "import sys\nopen(%r, 'a').write('helper ' + ' '.join(sys.argv[1:]) + '\\n')\n" % sh.calls, base=sh.tmp)
            rc, out = sh.run('HELPER=%s; synced_after() { echo "2026/11/24 10:00:00"; }; fi_raw_off' % helper)
            self.assertIn("helper policy-unclassified off", sh.called(), out)
        finally:
            sh.close()


# ------------------------------------------------------------------------------------------------ 8. decision 5b
def ism(pid, patterns, states, default="hot"):
    return {"_id": pid, "policy": {"policy_id": pid, "default_state": default, "states": states,
                                   "ism_template": [{"index_patterns": patterns}] if patterns else None}}


HOT_DELETE = lambda age: [{"name": "hot", "actions": [], "transitions": [{"state_name": "delete", "conditions": {"min_index_age": age}}]},
                          {"name": "delete", "actions": [{"delete": {}}], "transitions": []}]


class RetentionFromTheSourceDecision5b(unittest.TestCase):
    def test_the_delete_age_of_a_policy_covering_the_alert_indices(self):
        pols = {"policies": [ism("wazuh-alerts-retention", ["wazuh-alerts-*"], HOT_DELETE("90d")),
                             ism("archives", ["wazuh-archives-*"], HOT_DELETE("7d")),
                             ism("other", ["logs-*"], HOT_DELETE("1d"))]}
        r = H.retention_4x_of(pols, {})
        self.assertEqual(r["retention_days"], 90)
        self.assertEqual([p["policy_id"] for p in r["policies"]], ["wazuh-alerts-retention"])

    def test_a_policy_attached_by_hand_counts_and_the_longest_wins(self):
        pols = {"policies": [ism("short", ["wazuh-alerts-4.x-*"], HOT_DELETE("30d")), ism("manual", None, HOT_DELETE("2160h"))]}
        ex = {"wazuh-alerts-4.x-2026.01.01": {"index.plugins.index_state_management.policy_id": "manual"}, "total_managed_indices": 1}
        r = H.retention_4x_of(pols, ex)
        self.assertEqual(r["retention_days"], 90)
        self.assertEqual(sorted(p["policy_id"] for p in r["policies"]), ["manual", "short"])

    def test_a_delete_on_another_condition_is_not_an_age(self):
        st = [{"name": "hot", "actions": [], "transitions": [{"state_name": "delete", "conditions": {"min_doc_count": 5}}]},
              {"name": "delete", "actions": [{"delete": {}}]}]
        r = H.retention_4x_of({"policies": [ism("docs", ["wazuh-alerts-*"], st)]}, {})
        self.assertIsNone(r["retention_days"])
        self.assertIn("does not depend on the index's age", r["policies"][0]["how"])

    def test_a_refused_read_stops(self):
        with mock.patch.dict(os.environ, {"V4_INDEXER_ADMIN_PASSWORD": "x"}), \
                mock.patch.object(H, "idx", lambda *a, **k: (403, {"error": "forbidden"})):
            rc, out = quiet(H.retention_4x, os.path.join(tempfile.gettempdir(), "of1-never-written.json"))
        self.assertEqual(rc, 1)
        self.assertIn("refused", out)

    def retention(self, script, setting=None, recorded=None):
        sh = helpers.Shell(script)
        try:
            if recorded is not None:
                sh.write("retention-4x.json", recorded)
            env = {"HISTORY_RETENTION": setting} if setting is not None else {}
            rc, out = sh.run('if declare -F history_retention >/dev/null; then history_retention; cat "$STATE/history.retention"; '
                             'else echo "$HISTORY_RETENTION"; fi', env=env)
            return out
        finally:
            sh.close()

    def test_the_4x_retention_is_the_default_and_the_report_says_why(self):
        rec = {"retention_days": 90, "policies": [{"policy_id": "wazuh-alerts-retention", "delete_after_days": 90}]}
        out = self.retention(MIGRATE, recorded=rec)
        self.assertEqual(out.splitlines()[0], "90d")
        self.assertIn("the 4.x deployment's own retention: ISM policy wazuh-alerts-retention deletes alert indices after 90 days", out)


    def test_an_explicit_setting_wins(self):
        out = self.retention(MIGRATE, setting="30d", recorded={"retention_days": 90, "policies": []})
        self.assertEqual(out.splitlines()[0], "30d")
        self.assertIn("set explicitly (HISTORY_RETENTION=30d)", out)

    def test_no_deleting_policy_gives_365_days_and_says_so(self):
        out = self.retention(MIGRATE, recorded={"retention_days": None, "policies": []})
        self.assertEqual(out.splitlines()[0], "365d")
        self.assertIn("no ISM policy deleted the 4.x alert indices", out)

    def test_the_loader_gets_it_and_the_precopy_reads_it_before_the_dump(self):
        t = open(MIGRATE).read()
        self.assertIn('--retention "$(history_retention)"', t)
        self.assertLess(t.index("step precopy.retention"), t.index("step precopy.history "))


# ------------------------------------------------------------------------------------------------ 9. decision 5a
class ArchivesOptInDecision5a(unittest.TestCase):
    CAT = "120 1048576\n80 2097152\n"

    def assess(self, script, setting=None, cat=CAT):
        sh = helpers.Shell(script)
        try:
            env = {"HISTORY_ARCHIVES": setting} if setting is not None else {}
            return sh.run('idx4() { printf "%s"; }; if declare -F assess_archives >/dev/null; then assess_archives; fi; echo "FAILS=$FAILS WARNS=$WARNS"' % cat, env=env)
        finally:
            sh.close()

    def test_assess_reports_their_size_and_the_setting_by_default(self):
        rc, out = self.assess(MIGRATE)
        self.assertIn("archives: 200 archived events in 2 daily indices (3 MB) are NOT carried (decision 5a", out)
        self.assertIn("HISTORY_ARCHIVES=1 is the setting that asks for them", out)
        self.assertIn("FAILS=0 WARNS=1", out)

    def test_asking_for_them_is_refused_with_what_is_missing(self):
        rc, out = self.assess(MIGRATE, "1")
        self.assertIn("FAILS=1", out)
        self.assertIn("this version loads alerts only", out)

    def test_no_archives_nothing_to_say(self):
        rc, out = self.assess(MIGRATE, cat="")
        self.assertIn("archives: no wazuh-archives-4.x-* index", out)


    def test_the_loader_skips_archive_indices_today(self):
        """Why the opt-in is not built (MERGE-LOG OF1 item 9): a bundle holding an archives index loads nothing of it."""
        t = tempfile.mkdtemp()
        try:
            man = {"indices": {"wazuh-alerts-4.x-2026.01.02": {"docs_expected": 3, "complete": True, "files": []},
                               "wazuh-archives-4.x-2026.01.02": {"docs_expected": 9, "complete": True, "files": []}}}
            write(os.path.join(t, "manifest.json"), json.dumps(man))
            HL = helpers.load(os.path.join(SRC, "history_load.py"), "of1_history_load_b", extra_path=SRC)
            b = HL.Bundle(t)
            self.assertEqual(b.skipped, ["wazuh-archives-4.x-2026.01.02"])
            self.assertEqual(b.total(), 3)
        finally:
            shutil.rmtree(t, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ 10. decision 10
HL = helpers.load(os.path.join(SRC, "history_load.py"), "of1_history_load", extra_path=SRC)


class FakeIndexer:
    """The indexer as the loader sees it: _nodes/stats/breaker answers from a script of parent-breaker use, _bulk refuses
    as scripted (a whole-request circuit_breaking_exception, then one document refused inside a batch), else creates."""

    def __init__(self, breaker_use, bulk_script, clock):
        self.use, self.script, self.clock = list(breaker_use), list(bulk_script), clock
        self.log, self.created = [], set()

    def __call__(self, method, path, body=None, timeout=600):
        if path.startswith("/_nodes/stats/breaker"):
            u = self.use.pop(0) if len(self.use) > 1 else self.use[0]
            self.log.append(("breaker", self.clock.t, u))
            return 200, {"nodes": {"n1": {"name": "node-1", "breakers": {"parent": {"limit_size_in_bytes": 1000, "estimated_size_in_bytes": int(u * 1000)}}}}}
        if "/_bulk" in path:
            lines = body.split(b"\n")
            acts = [json.loads(l) for l in lines[0::2] if l.strip()]
            step = self.script.pop(0) if self.script else "ok"
            self.log.append(("bulk", self.clock.t, step, len(acts)))
            if step == "cbe":
                return 429, {"error": {"type": "circuit_breaking_exception", "reason": "[parent] Data too large"}, "status": 429}
            items = []
            for i, x in enumerate(acts):
                if step == "item429" and i == 0:
                    items.append({"create": {"status": 429, "_id": x["create"]["_id"], "error": {"type": "circuit_breaking_exception"}}})
                else:
                    self.created.add(x["create"]["_id"])
                    items.append({"create": {"status": 201, "_id": x["create"]["_id"], "_index": x["create"]["_index"]}})
            return 200, {"errors": step != "ok", "items": items}
        return 404, {}


class _Clock:
    def __init__(self):
        self.t, self.sleeps = 0.0, []

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s

    def now(self):
        return self.t


class _LoaderBundle(unittest.TestCase):
    """A one-file history bundle (5 alerts of one day) and a load through a fake indexer."""
    DOC = {"timestamp": "2026-01-02T03:04:05.000+0000", "rule": {"id": "5501", "level": 3, "description": "x", "groups": ["pam"]},
           "agent": {"id": "001", "name": "a"}, "manager": {"name": "m"}, "full_log": "hello", "location": "/var/log/auth.log"}

    def setUp(self):
        import gzip
        self.t = tempfile.mkdtemp(prefix="of1-loader-")
        os.makedirs(os.path.join(self.t, "data"))
        with gzip.open(os.path.join(self.t, "data", "f1.ndjson.gz"), "wb") as f:
            for i in range(5):
                f.write(json.dumps({"_id": "d%d" % i}).encode() + b"\n" + json.dumps(dict(self.DOC, id=str(i))).encode() + b"\n")
        self.f = {"index": "wazuh-alerts-4.x-2026.01.02", "file": "data/f1.ndjson.gz", "docs": 5}
        write(os.path.join(self.t, "manifest.json"), json.dumps({"indices": {self.f["index"]: {"docs_expected": 5, "complete": True, "files": [self.f]}}}))

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def load(self, mod, use, script, **kw):
        clock = _Clock()
        fake = FakeIndexer(use, script, clock)
        a = mock.Mock(cluster_name="wazuh", agent_ids="carried", agent_registry=None, bulk_docs=2, bulk_bytes=1 << 20, **kw)
        b = mod.Bundle(self.t)
        rej = {"lock": __import__("threading").Lock(), "f": io.StringIO()}
        p = [mock.patch.object(mod.hm, "Api", lambda a_: fake), mock.patch.object(mod.time, "sleep", clock.sleep),
             mock.patch.object(mod, "load_registry", lambda a_: {})]
        if hasattr(mod, "SLEEP"):
            p += [mock.patch.object(mod, "SLEEP", clock.sleep), mock.patch.object(mod, "CLOCK", clock.now)]
        with contextlib.ExitStack() as st:
            for x in p:
                st.enter_context(x)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    stats = mod.load_file(a, b, self.f, mod._NoState(), rej)
                except RuntimeError as e:
                    stats = e
        return stats, fake, clock, buf.getvalue()



class LoaderBacksOffBeforeTheBreakerDecision10(_LoaderBundle):
    def test_the_load_pauses_while_the_parent_breaker_is_high(self):
        stats, fake, clock, out = self.load(HL, [0.97, 0.99, 0.60], [], breaker_max=0.85, breaker_wait_max=1800)
        first_bulk = next(e for e in fake.log if e[0] == "bulk")
        self.assertEqual([e[2] for e in fake.log if e[0] == "breaker"][:3], [0.97, 0.99, 0.60])
        self.assertGreaterEqual(first_bulk[1], 6.0)            # 2 s + 4 s of pause before anything was sent
        self.assertIn("parent at 97.0 % of its limit on node-1", out)
        self.assertEqual(len(fake.created), 5)
        self.assertEqual(stats["paused_s"], 6.0)


    def test_a_circuit_breaking_exception_is_retried_with_backoff(self):
        stats, fake, clock, out = self.load(HL, [0.10], ["cbe", "cbe", "item429"], breaker_max=0.85, breaker_wait_max=1800)
        self.assertNotIsInstance(stats, Exception, out)
        self.assertEqual(len(fake.created), 5)
        self.assertEqual(stats["refused_batches"], 2)
        self.assertEqual(stats["retried"], 1)
        self.assertEqual(clock.sleeps[:3], [1.0, 2.0, 4.0])      # doubling backoff, then the item retry


    def test_pressure_that_never_ends_stops_the_load_resumable(self):
        stats, fake, clock, out = self.load(HL, [0.99], [], breaker_max=0.85, breaker_wait_max=120)
        self.assertIsInstance(stats, RuntimeError)
        self.assertIn("resumes with the same command", str(stats))
        self.assertFalse(fake.created)

    def test_an_unreadable_breaker_does_not_stop_the_load(self):
        class NoStats(FakeIndexer):
            def __call__(self, method, path, body=None, timeout=600):
                if path.startswith("/_nodes/stats"):
                    return 403, {"error": "no permissions"}
                return super().__call__(method, path, body, timeout)
        with mock.patch(__name__ + ".FakeIndexer", NoStats):
            stats, fake, clock, out = self.load(HL, [0.10], [], breaker_max=0.85, breaker_wait_max=1800)
        self.assertEqual(len(fake.created), 5, (stats, out))
        self.assertIn("cannot read _nodes/stats/breaker (HTTP 403)", out)


# ------------------------------------------------------------------------------------------------ 11. decision 9
SC = helpers.load(os.path.join(SRC, "snap_consolidate.py"), "of1_snap_consolidate", extra_path=SRC)


class ScrollingIndexer(FakeIndexer):
    """A restored 4.x daily copy on the 5.0 indexer, served by scroll pages of two."""

    def __init__(self, docs, clock):
        FakeIndexer.__init__(self, [0.1], [], clock)
        self.docs, self.pos, self.bodies, self.cleared = docs, 0, [], False

    def page(self):
        h = self.docs[self.pos:self.pos + 2]
        self.pos += 2
        return 200, {"_scroll_id": "s1", "hits": {"hits": [{"_id": i, "_source": d} for i, d in h]}}

    def __call__(self, method, path, body=None, timeout=600):
        if "/_search?scroll=" in path:
            return self.page()
        if path == "/_search/scroll":
            return (200, {}) if method == "DELETE" and not setattr(self, "cleared", True) else self.page()
        if "/_bulk" in path:
            self.bodies.append(body)
        return super().__call__(method, path, body, timeout)


class SnapshotThroughThePythonLoaderDecision9(_LoaderBundle):
    def docs(self):
        import gzip
        with gzip.open(os.path.join(self.t, "data", "f1.ndjson.gz"), "rb") as f:
            lines = f.read().splitlines()
        return [(json.loads(m)["_id"], json.loads(d)) for m, d in zip(lines[0::2], lines[1::2])]

    def test_a_restored_index_is_shaped_exactly_as_its_dump(self):
        clock = _Clock()
        a = mock.Mock(cluster_name="wazuh", agent_ids="carried", agent_registry=None, bulk_docs=2, bulk_bytes=1 << 20,
                      breaker_max=0.85, breaker_wait_max=1800)
        b = HL.Bundle(self.t)
        rej = {"lock": __import__("threading").Lock(), "f": io.StringIO()}
        fake_i = ScrollingIndexer(self.docs(), clock)
        fake_f = ScrollingIndexer([], clock)
        with mock.patch.object(HL, "SLEEP", clock.sleep), mock.patch.object(HL, "CLOCK", clock.now), \
                mock.patch.object(HL, "load_registry", lambda a_: {}), contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(HL.hm, "Api", lambda a_: fake_i):
                src, st = HL.load_index(a, b, self.f["index"], rej)
            with mock.patch.object(HL.hm, "Api", lambda a_: fake_f):
                HL.load_file(a, b, self.f, HL._NoState(), rej)
        self.assertEqual(st["created"], 5)
        self.assertEqual(fake_i.bodies, fake_f.bodies)          # the same ids, targets and shaped documents
        self.assertIn(b'"_id": "wazuh-alerts-4.x-2026.01.02:d0"', fake_i.bodies[0])
        self.assertTrue(fake_i.cleared)

    def test_a_short_read_of_the_restored_copy_fails(self):
        clock = _Clock()
        a = mock.Mock(cluster_name="wazuh", agent_ids="carried", agent_registry=None, bulk_docs=2, bulk_bytes=1 << 20,
                      breaker_max=0, breaker_wait_max=1800)
        fake = ScrollingIndexer(self.docs()[:4], clock)
        with mock.patch.object(HL.hm, "Api", lambda a_: fake), mock.patch.object(HL, "load_registry", lambda a_: {}), \
                self.assertRaises(RuntimeError) as e:
            HL.load_index(a, HL.Bundle(self.t), self.f["index"], {"lock": __import__("threading").Lock(), "f": io.StringIO()})
        self.assertIn("4 documents read from the restored copy, the 4.x source had 5", str(e.exception))

    def consolidate(self, mod):
        loaded, counted = [], {"n": 0}
        src = self.f["index"]
        write(os.path.join(self.t, "indices", src + ".json"), json.dumps({"shards": 1, "mappings": {}}))

        def api(method, path, body=None, timeout=600):
            if path.startswith("/_cluster/health"):
                return 200, {"active_shards": 1, "unassigned_shards": 0, "initializing_shards": 0, "status": "green", "number_of_data_nodes": 1}
            if path.startswith("/_snapshot/sc1-history/") and method == "GET":
                return 200, {"snapshots": [{"indices": [src]}]}
            if path.startswith("/_plugins/_ism/policies/") and method == "GET":
                return 404, {}
            if path.startswith("/_cat/indices"):
                return 200, []
            if method == "HEAD":
                return 404, {}
            return 200, {}

        def counts(api_, srcs):
            counted["n"] += 1
            return {src: 5} if loaded else {}

        def load_index(a, b, n, rej):
            loaded.append(n)
            return n, {"docs": 5, "created": 5, "existing": 0, "rejected": 0}
        a = types_ns(repo_path="/var/lib/wazuh-migration/repo", meta=self.t, months=None, shard_ceiling=0.9, restore_rate=None,
                     snapshot="snap", cluster_name="wazuh", agent_ids="carried", agent_registry=None, priority=500, retention="365d",
                     parallel=2, verbose=False, forcemerge=False, timings=None, state_dir=os.path.join(self.t, "ls"),
                     allow_unshaped=False, batch=1000, slices="auto", bulk_docs=2, bulk_bytes=1 << 20)
        p = [mock.patch.object(mod.hl, "build_template", lambda *x, **k: ({}, 0, {})), mock.patch.object(mod.hl, "load_registry", lambda a_: {}),
             mock.patch.object(mod.hl, "count", lambda *x: 5), mock.patch.object(mod, "per_source_counts", counts),
             mock.patch.object(mod.hm, "policy_body", lambda a_: {"policy": {}}),
             mock.patch.object(sys, "path", [os.path.dirname(mod.__file__)] + sys.path)]   # snap_consolidate imports snapshot_repo beside it
        if hasattr(mod.hl, "load_index"):
            p.append(mock.patch.object(mod.hl, "load_index", load_index))
        with contextlib.ExitStack() as st:
            for x in p:
                st.enter_context(x)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    rc = mod.cmd_consolidate(api, a)
                except SystemExit as e:
                    rc = e
        return rc, loaded, buf.getvalue()

    def test_consolidate_feeds_each_restored_index_to_the_python_loader(self):
        rc, loaded, out = self.consolidate(SC)
        self.assertEqual(rc, 0, out)
        self.assertEqual(loaded, [self.f["index"]])
        self.assertIn("shaped and loaded 5 documents", out)



def types_ns(**k):
    import types
    return types.SimpleNamespace(**k)


# ------------------------------------------------------------------------------------------------ 12. latest 4.14.x only
class SourceIsTheLatest414Item12(unittest.TestCase):
    def check(self, rows):
        series, minimum = H.source_policy()
        return H.source_versions_check(rows, series, minimum)

    def test_the_manifest_holds_the_minimum_as_data(self):
        self.assertEqual(H.source_policy(), ("4.14", "4.14.10"))

    def test_an_older_414_is_refused_naming_the_version_and_what_to_do(self):
        bad, good = self.check([("aio", "wazuh-manager", "4.14.10-1"), ("aio", "wazuh-indexer", "4.14.9-1"), ("aio", "wazuh-dashboard", "4.14.10-1")])
        self.assertEqual(len(bad), 1, bad)
        self.assertIn("wazuh-indexer 4.14.9-1 on aio is older than 4.14.10", bad[0])
        self.assertIn("upgrade every node to the latest 4.14.x first", bad[0])

    def test_the_minimum_and_a_newer_414_are_accepted(self):
        bad, good = self.check([("aio", c, v) for c in H.SOURCE_COMPONENTS for v in ("4.14.10-1", "4.14.11-1")])
        self.assertEqual(bad, [])
        self.assertIn("wazuh-manager 4.14.11-1 on aio (a 4.14.x newer than 4.14.10: accepted)", good)

    def test_another_series_is_not_a_414_source(self):
        bad, _ = self.check([("aio", "wazuh-manager", "4.15.0-1"), ("aio", "wazuh-indexer", "5.0.0-1"), ("aio", "wazuh-dashboard", "4.13.2-1")])
        self.assertEqual(len(bad), 3)
        self.assertTrue(all("is not a 4.14 source" in b for b in bad), bad)

    def test_a_mixed_version_cluster_is_refused_naming_the_node(self):
        class FakeApi:
            def __init__(self, pw):
                pass

            def get(self, path):
                return [{"name": "wazuh-1", "type": "master", "version": "4.14.10"}, {"name": "wazuh-2", "type": "worker", "version": "4.14.9"}]
        with mock.patch.object(H, "Api", FakeApi), mock.patch.dict(os.environ, {"V4_API_PASSWORD": "x"}):
            rc, out = quiet(H.source_version_cluster)
        self.assertEqual(rc, 1)
        self.assertIn("SOURCE VERSION REFUSED: wazuh-manager 4.14.9 on wazuh-2 is older than 4.14.10", out)
        self.assertIn("source version: wazuh-manager 4.14.10 on wazuh-1", out)

    def shell(self, script, versions):
        sh = helpers.Shell(script)
        body = 'case "${@: -1}" in %s *) exit 1;; esac' % " ".join('%s) printf "installed %s";;' % (k, v) for k, v in versions.items())
        sh.stub("dpkg-query", body)
        return sh

    def test_precopy_refuses_a_4149_source_before_any_step_even_forced(self):
        v = {"wazuh-manager": "4.14.9-1", "wazuh-indexer": "4.14.9-1", "wazuh-dashboard": "4.14.9-1"}
        sh = self.shell(MIGRATE, v)
        try:
            rc, out = sh.run('step() { echo "STEP $1"; }; load_v4_passwords() { :; }; phase_precopy', env={"FORCE_BUILDS": "1"})
        finally:
            sh.close()
        self.assertNotEqual(rc, 0, out)
        self.assertNotIn("STEP", out)
        self.assertIn("is older than 4.14.10", out)


    def test_a_41411_source_goes_on(self):
        sh = self.shell(MIGRATE, {"wazuh-manager": "4.14.11-1", "wazuh-indexer": "4.14.11-1", "wazuh-dashboard": "4.14.11-1"})
        try:
            rc, out = sh.run('step() { echo "STEP $1"; }; load_v4_passwords() { :; }; phase_precopy')
        finally:
            sh.close()
        self.assertIn("STEP precopy.truth", out)

    def test_the_cluster_node_step_refuses_an_old_node(self):
        t = tempfile.mkdtemp(prefix="of1-node-")
        try:
            b = os.path.join(t, "bin")
            os.makedirs(b)
            write(os.path.join(b, "rpm"), '#!/bin/bash\ncase "${@: -1}" in wazuh-indexer) echo 4.14.9-1;; *) echo "package ${@: -1} is not installed";; esac\n')
            os.chmod(os.path.join(b, "rpm"), 0o755)
            env = dict(os.environ, PATH=b + ":" + os.environ["PATH"], BUNDLE_DIR=os.path.join(t, "bundle"), SRC=SRC, PYTHONDONTWRITEBYTECODE="1", PKGFAM="rpm")   # CL1: nodes detect deb too
            p = subprocess.run(["bash", os.path.join(SRC, "cluster", "node", "source-version.sh")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = p.stdout.decode()
        finally:
            shutil.rmtree(t, ignore_errors=True)
        self.assertNotEqual(p.returncode, 0, out)
        self.assertIn("wazuh-indexer 4.14.9-1 on", out)
        self.assertIn("FATAL: this node's 4.x is not the latest 4.14.x", out)


if __name__ == "__main__":
    unittest.main()
