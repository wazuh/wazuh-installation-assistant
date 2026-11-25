"""migrate.sh: the fixes folded from R2, F5, F6, F7 and F10, and the conflicts resolved between them."""
import os
import re
import subprocess
import time
import unittest

import helpers

MERGED = os.path.join(helpers.SRC, "migrate.sh")

IPT_OFF = 'case "$1" in -C) exit 1;; *) exit 0;; esac'     # iptables: no rule present (as after a reboot)


class ShellCase(unittest.TestCase):
    script = MERGED

    def setUp(self):
        self.sh = helpers.Shell(self.script)
        for c in ("systemctl", "sleep", "ss", "nft", "curl", "firewall-cmd"):
            self.sh.stub(c)
        self.sh.stub("iptables", IPT_OFF)

    def tearDown(self):
        self.sh.close()


class SyntaxAndStatic(unittest.TestCase):
    def test_every_shell_script_parses(self):
        bad = []
        for r, _, fs in os.walk(helpers.SRC):
            for f in fs:
                if f.endswith(".sh"):
                    p = subprocess.run(["bash", "-n", os.path.join(r, f)], stderr=subprocess.PIPE)
                    if p.returncode:
                        bad.append((f, p.stderr.decode()[:200]))
        self.assertEqual(bad, [])

    def test_verify_bundle_never_skipped_by_its_marker_F6(self):
        """F6 (rule 12): the run loop must run verify_bundle again even when its phase marker exists."""
        txt = open(MERGED).read()
        self.assertIn('[ "$CUR" != verify_bundle ]', txt)

    def test_saved_objects_import_on_going_back_tolerates_a_starting_dashboard_R2(self):
        """R2: curl exit 7 while the 4.x dashboard starts ended the step (AMI); the call now tolerates it."""
        pat = re.compile(r'back-so\.out.*saved-objects\.ndjson;filename=v4\.ndjson" \|\| true\)')
        self.assertRegex(open(MERGED).read(), pat)

    def test_no_merge_markers_left(self):
        for r, _, fs in os.walk(helpers.SRC):
            for f in fs:
                if f.endswith((".py", ".sh", ".json")):
                    t = open(os.path.join(r, f), errors="replace").read()
                    self.assertIsNone(re.search(r"^(<<<<<<<|>>>>>>>) ", t, re.M), f)


class GuardResumeF5(ShellCase):
    def test_reboot_emptied_firewall_guard_is_put_back(self):
        """F5 (rule 10): the record says the guard is on, the firewall (after a reboot) does not have it."""
        self.sh.write("state/guard.required.agent", "2026-11-24T00:00:00Z\n")
        rc, out = self.sh.run("guard_resume")
        self.assertEqual(rc, 0, out)
        self.assertIn("putting it back", out)
        self.assertIn("iptables -I INPUT 1 -j MIGGUARD", self.sh.called())

    def test_old_record_of_earlier_bundles_is_honoured(self):
        self.sh.write("state/guard.on", "2026-11-24T00:00:00Z\n")
        rc, out = self.sh.run("guard_resume")
        self.assertIn("iptables -I INPUT 1 -j MIGGUARD", self.sh.called())



class PackageRepairF5(ShellCase):
    def test_half_configured_package_is_repaired_before_an_assistant(self):
        """F5 (rule 10): dpkg-query reports wazuh-manager half-configured until a forced purge runs."""
        flag = os.path.join(self.sh.tmp, "purged")
        self.sh.stub("dpkg-query", 'sep=" "; case "$*" in *"Package}:"*) sep=":";; esac; '
                                   '[ -e %s ] && echo "wazuh-manager${sep}not-installed" || echo "wazuh-manager${sep}half-configured"' % flag)
        self.sh.stub("dpkg", 'case "$1" in --configure) exit 1;; --purge) touch %s;; esac' % flag)
        rc, out = self.sh.run('pkgdb_problems; echo ---; pkg_repair test')
        self.assertIn("package wazuh-manager is half-configured", out)
        self.assertEqual(rc, 0, out)
        self.assertIn("clean after the repair", out)
        self.assertTrue(any(c.startswith("dpkg --purge --force-remove-reinstreq wazuh-manager") for c in self.sh.called()))

    def test_install_and_removal_call_the_repair(self):
        txt = open(MERGED).read()
        self.assertIn('pkg_repair "before the 5.0 assistant"', txt)
        self.assertIn('pkg_repair "before the 5.0 removal"', txt)
        self.assertIn('pkg_repair "before the 4.x removal"', txt)          # merged: rule 10, before either assistant


FEED_LOADED = ("2026/11/24 11:06:01 wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: Consumer 'x' is ready. Starting feed download.\n"
                 "2026/11/24 11:13:55 wazuh-manager-modulesd:vulnerability-scanner: INFO: CVE feed fully loaded.\n")


class FinishLegacy(ShellCase):
    def _setup(self, sh, status):
        conf = sh.write("etc/wazuh-manager/wazuh-manager.conf",
                        "<ossec_config><remote><legacy><enabled>yes</enabled></legacy></remote></ossec_config>\n", base=sh.root)
        os.makedirs(os.path.join(sh.root, "var/wazuh-manager/bin"), exist_ok=True)
        v = os.path.join(sh.root, "var/wazuh-manager/bin/wazuh-manager-conf")
        open(v, "w").write("#!/bin/sh\nexit 0\n"); os.chmod(v, 0o755)
        sh.write("legacy.txt", status, base=sh.tmp)
        os.makedirs(os.path.join(sh.root, "var/wazuh-manager/logs"), exist_ok=True)     # rule 14: the feed has loaded
        sh.write("var/wazuh-manager/logs/wazuh-manager.log", FEED_LOADED, base=sh.root)
        return conf

    def test_backup_of_the_configuration_is_taken_once_F5(self):
        """F5 (cut 4a): a rerun after a kill must not replace the only copy with the already-edited file."""
        conf = self._setup(self.sh, "legacy channel can be closed: YES\n")
        open(conf + ".before-legacy-off", "w").write("ORIGINAL\n")
        rc, out = self.sh.run('fu() { cat %s/legacy.txt; }; fi_legacy' % self.sh.tmp)
        self.assertEqual(open(conf + ".before-legacy-off").read(), "ORIGINAL\n", out)
        self.assertIn("<enabled>no</enabled>", open(conf).read())


    NC = ("legacy channel can be closed: NO\nagents not on 5.x in the registry: 1: 002 (None, never_connected)\n"
          "legacy TCP sessions per node: node01=0\n")

    def test_never_connected_agents_keep_the_ports_by_default_F6(self):
        """F6 (rule 13): never-connected agents do not fail the finish; default keep, recorded for the next steps."""
        conf = self._setup(self.sh, self.NC)
        rc, out = self.sh.run('fu() { cat %s/legacy.txt; }; fi_legacy' % self.sh.tmp)
        self.assertEqual(rc, 0, out)
        self.assertIn("keep never-connected: 002", open(os.path.join(self.sh.bundle, "state/legacy.open")).read())
        self.assertIn("<enabled>yes</enabled>", open(conf).read())

    def test_never_connected_close_by_decision_F6(self):
        conf = self._setup(self.sh, self.NC)
        rc, out = self.sh.run('fu() { cat %s/legacy.txt; }; fi_legacy' % self.sh.tmp, env={"NEVER_CONNECTED_AT_FINISH": "close"})
        self.assertIn("<enabled>no</enabled>", open(conf).read(), out)


    def test_an_agent_that_reported_4x_keeps_the_ports_whatever_the_decision(self):
        conf = self._setup(self.sh, "legacy channel can be closed: NO\nagents not on 5.x in the registry: 1: 004 (v4.14.10, active)\n")
        rc, out = self.sh.run('fu() { cat %s/legacy.txt; }; fi_legacy' % self.sh.tmp, env={"NEVER_CONNECTED_AT_FINISH": "close"})
        self.assertIn("LEGACY PORTS KEPT OPEN", out)
        self.assertIn("<enabled>yes</enabled>", open(conf).read())


class SecretsByValueF6(ShellCase):
    KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    def _bundle(self, sh):
        sh.write("v4/etc/client.keys", "001 ag1 any %s\n" % self.KEY)
        sh.write("identity/manifest.json", "{}")
        sh.write("results/precopy.log", "a copy of the key left in a log: %s\n" % self.KEY)

    def test_a_carried_secret_left_outside_the_deleted_parts_is_found(self):
        """F6 (rule 13): secrets are found by value, not by a list of directories."""
        self._bundle(self.sh)
        rc, out = self.sh.run("fi_secrets", env={"MIG_SECRETS_TMP": self.sh.tmp})
        self.assertNotEqual(rc, 0, out)
        self.assertIn("key of agent 001 in", out)
        self.assertFalse(os.path.exists(os.path.join(self.sh.bundle, "v4/etc")))

    def test_clean_bundle_passes(self):
        self.sh.write("v4/etc/client.keys", "001 ag1 any %s\n" % self.KEY)
        rc, out = self.sh.run("fi_secrets", env={"MIG_SECRETS_TMP": self.sh.tmp})
        self.assertEqual(rc, 0, out)



class StaleBundleF6(ShellCase):
    def test_a_source_running_again_after_the_freeze_is_refused(self):
        """F6 (rule 12): the bundle is valid only for the source it froze; a marker never skips the check."""
        self.sh.write("state/T_manager4_stopped", "2026-11-24T00:00:00Z\n")
        self.sh.stub("systemctl", 'case "$1 $2" in "is-active -q") [ "$3" = wazuh-manager ] && exit 0; exit 3;; '
                                  '"show wazuh-manager") echo "Tue 2026-11-24 01:00:00 UTC";; esac; exit 0')
        rc, out = self.sh.run("vb_source")
        self.assertNotEqual(rc, 0)
        self.assertIn("REFUSED: wazuh-manager is running now", out)
        self.assertIn("REFUSED: wazuh-manager was started again", out)



class NoAgentSourceF6(ShellCase):
    def test_usable_keys_ignores_removed_and_commented_entries(self):
        p = self.sh.write("k", "001 a any key1\n002 !b any key2\n#003 c any k\n", base=self.sh.tmp)
        rc, out = self.sh.run("usable_keys %s; : > %s; usable_keys %s" % (p, p, p))
        self.assertEqual(out.split(), ["1", "0"])

    def test_noagents_skips_reconcile_and_agents_phase(self):
        self.sh.write("identity-noagents/MANIFEST", "x")
        self.sh.write("state/confirm.no_return", "x")
        rc, out = self.sh.run("cmd_agents; echo rc=$?")
        self.assertIn("nothing to upgrade", out)
        self.assertTrue(os.path.exists(os.path.join(self.sh.bundle, "state/phase.agents")))


class GoingBackF7F10(ShellCase):
    def test_guard_goes_on_before_the_manager_stops_R2_F7(self):
        """R2/F7 (rule 11): the guard is on before the 5.0 manager stops on the way back."""
        rc, out = self.sh.run("bk_stop5")
        calls = self.sh.called()
        on = next(i for i, c in enumerate(calls) if c == "iptables -I INPUT 1 -j MIGGUARD")
        stop = next(i for i, c in enumerate(calls) if c.startswith("systemctl stop wazuh-manager"))
        self.assertLess(on, stop, calls)
        self.assertTrue(os.path.exists(os.path.join(self.sh.bundle, "state/guard.required.agent")))


    def test_going_back_stops_a_running_history_load_F10(self):
        """F10: going back stops a load running after the opening before 5.0 is removed."""
        p = subprocess.Popen(["bash", "-c", "exec -a 'python3 history_load.py apply --bundle /nonexistent-migtest' sleep 120"])
        try:
            time.sleep(0.5)
            rc, out = self.sh.run("bk_stop_history")
            self.assertIn("a history load is running", out)
            self.assertEqual(rc, 0, out)
            p.wait(timeout=30)
        finally:
            if p.poll() is None:
                p.kill()

    def test_offline_4x_reinstall_from_the_bundle_F7(self):
        """F7: with V4_PACKAGES_CACHE=1 going back runs the 4.x assistant in offline mode from the kept packages."""
        args = os.path.join(self.sh.tmp, "assistant-args")
        self.sh.write("v4/wazuh-install.sh", 'echo "$@" > %s\n' % args)
        self.sh.write("v4/offline/wazuh-offline.tar.gz", "pkgs")
        subprocess.run("cd %s/v4/offline && sha256sum wazuh-offline.tar.gz > wazuh-offline.tar.gz.sha256" % self.sh.bundle, shell=True)
        self.sh.stub("dpkg", "exit 0")
        self.sh.stub("dpkg-query", "exit 0")
        rc, out = self.sh.run("bk_install4", env={"V4_PACKAGES_CACHE": "1"})
        self.assertIn("-of", open(args).read().split(), out)


class HistoryAfterOpenF10(ShellCase):
    def setUp(self):
        super().setUp()
        self.sh.stub("dpkg-query", 'echo "installed 5.0.0-1"')
        self.step_stub = 'step() { echo "STEP $1"; }; '

    def test_finish_is_refused_until_the_history_is_on(self):
        """F10: finish deletes history/data, the only copy of the 4.x alerts once 4.x is gone."""
        self.sh.write("state/phase.agents", "x")
        rc, out = self.sh.run("cmd_finish")
        self.assertNotEqual(rc, 0)
        self.assertIn("the history is not loaded, proven and switched on yet", out)

    def test_custom_dashboards_follow_the_aliases_conflict_C6(self):
        """C6 (F10 x S5): after-open imports the custom dashboards in the history phase, after `on`, never in phase 6."""
        self.sh.write("state/replace.gate", "x")
        self.sh.write("state/open.gate", "x")
        rc, out = self.sh.run(self.step_stub + "phase_import; phase_history")
        steps = re.findall(r"^STEP (\S+)", out, re.M)
        self.assertNotIn("import.saved_objects", steps, out)
        self.assertNotIn("import.history_load", steps)
        self.assertLess(steps.index("history.on"), steps.index("history.saved_objects"))
        self.assertIn("import.history_roles", steps)

    def test_before_open_keeps_the_old_order(self):
        self.sh.write("state/replace.gate", "x")
        rc, out = self.sh.run(self.step_stub + "phase_import", env={"HISTORY_LOAD": "before-open"})
        steps = re.findall(r"^STEP (\S+)", out, re.M)
        self.assertLess(steps.index("import.history_on"), steps.index("import.saved_objects"))


class DecisionInForceF6(ShellCase):
    def _log(self, lines):
        os.makedirs(os.path.join(self.sh.root, "var/wazuh-manager/logs"), exist_ok=True)
        self.sh.write("var/wazuh-manager/logs/wazuh-manager.log", "\n".join(lines) + "\n", base=self.sh.root)

    def test_the_opening_waits_for_every_changed_space(self):
        """F6-D3 (rule 8): a decision touching custom (activate) and standard (raw) waits for both synchronisations."""
        self.sh.write("state/unclassified.applied", "activate\nraw\n")
        self.sh.write("state/T_decision_logtime", "2026/11/24 02:50:00\n")
        self._log(["2026/11/24 02:49:00 wazuh-manager-engine: INFO: Successfully synchronized space 'standard'",
                   "2026/11/24 02:51:10 wazuh-manager-engine: INFO: Hot swapped ... Successfully synchronized space 'custom'",
                   "2026/11/24 02:51:30 wazuh-manager-engine: INFO: Successfully synchronized space 'standard'"])
        rc, out = self.sh.run("op_in_force")
        self.assertEqual(rc, 0, out)
        self.assertIn("custom at 2026/11/24 02:51:10, standard at 2026/11/24 02:51:30", out)

    def test_open_phase_runs_it_between_decision_and_listeners(self):
        self.sh.write("state/import.gate", "x")
        self.sh.stub("dpkg-query", 'echo "installed 5.0.0-1"')
        rc, out = self.sh.run('step() { echo "STEP $1"; }; phase_open')
        steps = re.findall(r"^STEP (\S+)", out, re.M)
        self.assertEqual(steps[:3], ["open.decision", "open.in_force", "open.listeners"], out)



class ClusterDaemonRule4(ShellCase):
    def _ctl(self, body):
        os.makedirs(os.path.join(self.sh.root, "var/wazuh-manager/bin"), exist_ok=True)
        p = os.path.join(self.sh.root, "var/wazuh-manager/bin/cluster_control")
        open(p, "w").write("#!/bin/bash\n" + body + "\n")
        os.chmod(p, 0o755)

    def test_ready_waits_for_the_cluster_daemon_G5(self):
        flag = os.path.join(self.sh.tmp, "n")
        self._ctl('n=$(cat %s 2>/dev/null || echo 0); echo $((n+1)) > %s; [ "$n" -ge 2 ] && echo "node01 master" && exit 0; exit 124' % (flag, flag))
        rc, out = self.sh.run("wait_clusterd")
        self.assertEqual(rc, 0, out)
        self.assertEqual(open(flag).read().strip(), "3")

    def test_a_daemon_that_never_answers_fails_the_gate(self):
        self._ctl("exit 124")
        rc, out = self.sh.run("wait_clusterd", env={"CLUSTERD_TRIES": "2"})
        self.assertNotEqual(rc, 0)
        self.assertIn("does not answer", out)


class RaisedLimitRule15(ShellCase):
    def test_import_gate_refuses_while_the_api_limit_is_raised_G5(self):
        """Rule 15 (G5: a kill inside the raised window left the limit off until the rerun restored it)."""
        self.sh.write("identity-noagents/MANIFEST", "x")         # skip the API comparison; only the limit is under test
        self.sh.write("identity-stage/state.json", {"limit": {"state": "raised"}})
        rc, out = self.sh.run('set -o pipefail; im_gate')
        self.assertNotEqual(rc, 0, out)
        self.assertIn("is not restored", out)
        self.sh.write("identity-stage/state.json", {"limit": {"state": "restored"}})
        rc, out = self.sh.run('im_gate')
        self.assertEqual(rc, 0, out)

if __name__ == "__main__":
    unittest.main()
