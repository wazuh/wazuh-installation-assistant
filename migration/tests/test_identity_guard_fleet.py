"""Identity stage (F7's key check over G5), the shared guard (R2/F5 + K5, conflict C3), node-state.py, the fleet
orchestrator (A5 + A6, conflicts C10 to C13) and the agent configuration converters (AG1 + MAC1)."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock

import helpers

SRC = helpers.SRC
IS = helpers.load(os.path.join(SRC, "identity_stage.py"), "identity_stage_merged")
FU = helpers.load(os.path.join(SRC, "fleet-upgrade.py"), "fleet_upgrade_merged")


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


BY_ID = {"001": {"id": 1, "name": "ag1", "key": "K1"}, "002": {"id": 2, "name": "ag2", "key": "K2"}}


class CutImportF7(unittest.TestCase):
    def test_a_cut_import_of_this_bundle_resumes(self):
        eq, miss, wrong, foreign = IS.cut_import_check(BY_ID, {"001": ("ag1", "K1")})
        self.assertEqual((eq, miss, wrong, foreign), (["001"], ["002"], [], []))

    def test_a_self_enrolled_agent_under_a_bundle_id_is_named(self):
        eq, miss, wrong, foreign = IS.cut_import_check(BY_ID, {"001": ("ag2", "NEWKEY"), "005": ("x", "K5")})
        self.assertEqual((wrong, foreign), (["001"], ["005"]))

    def test_registry_keys_reads_usable_entries(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("001 ag1 any K1\n002 !ag2 any K2\n# c\n3 ag3 any K3\n")
        try:
            self.assertEqual(IS.registry_keys(f.name), {"001": ("ag1", "K1"), "003": ("ag3", "K3")})
        finally:
            os.unlink(f.name)

    def _run(self, mod, on_disk):
        d = tempfile.mkdtemp()
        try:
            json.dump({"agents": [dict(v, groups=["default"]) for v in BY_ID.values()], "groups": []}, open(os.path.join(d, "manifest.json"), "w"))
            args = types.SimpleNamespace(state=os.path.join(d, "st"), bundle=d, limit_mode="stock", raised_value=0, workers=1, chunk=500,
                                         max_passes=1, cooldown_wait=0, stop_after="inserts", with_password=False, with_rbac=False)
            touched = []
            patches = [mock.patch.object(mod, "read_api_yaml_limit", lambda: (300, None)),
                       mock.patch.object(mod, "Api", lambda *a, **k: types.SimpleNamespace(stats={}, set_budget=lambda v: None)),
                       mock.patch.object(mod, "preflight", lambda *a, **k: {"blockers": [], "conf_refused": []}),
                       mock.patch.object(mod, "read_registry", lambda api: ({"001": {"name": "ag2", "groups": ["default"]}}, {"default"})),
                       mock.patch.object(mod, "do_groups", lambda *a, **k: touched.append("groups") or (0, 0)),
                       mock.patch.object(mod, "do_inserts", lambda *a, **k: touched.append("inserts") or 0)]
            if hasattr(mod, "registry_keys"):
                patches.append(mock.patch.object(mod, "registry_keys", lambda path=None: on_disk))
            with contextlib.ExitStack() as st:
                for p in patches:
                    st.enter_context(p)
                r, out = quiet(mod.cmd_run, args)
            return r, out, touched
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_the_stage_refuses_before_writing_anything(self):
        r, out, touched = self._run(IS, {"001": ("ag2", "NEWKEY")})
        self.assertEqual(r, 3)
        self.assertIn("REFUSE", out)
        self.assertEqual(touched, [])



class SharedGuardC3(unittest.TestCase):
    """C3: R2/F5's chain guard and K5's node-state guard as one implementation (src/guard.sh)."""

    def setUp(self):
        self.t = tempfile.mkdtemp()
        b = os.path.join(self.t, "bin")
        os.makedirs(b)
        ipt = os.path.join(b, "iptables")
        open(ipt, "w").write('#!/bin/bash\necho "iptables $*" >> %(t)s/calls\nf=%(t)s/ipt_${@: -1}\n'
                             'case "$1" in -C) [ -e "$f" ];; -I) touch "$f";; -D) rm -f "$f";; -S) for x in %(t)s/ipt_*; do [ -e "$x" ] && echo "-A INPUT -j ${x##*ipt_}"; done;; esac\n'
                             % {"t": self.t})
        os.chmod(ipt, 0o755)
        for c in ("systemctl", "restorecon"):
            p = os.path.join(b, c)
            open(p, "w").write("#!/bin/sh\nexit 0\n")
            os.chmod(p, 0o755)
        self.env = dict(os.environ, PATH=b + ":" + os.environ["PATH"], MIG_GUARD_DROPIN_DIR=os.path.join(self.t, "dropin"),
                        MIG_GUARD_COPY=os.path.join(self.t, "copy.sh"))
        self.state = os.path.join(self.t, "state")

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def g(self, *args):
        p = subprocess.run(["bash", os.path.join(SRC, "guard.sh")] + list(args), env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode()

    def test_on_records_and_persists_a_reapply_before_any_manager_start_K5(self):
        rc, out = self.g("on", "cluster", self.state)
        self.assertEqual(rc, 0, out)
        self.assertIn("1516", out)
        self.assertTrue(os.path.exists(os.path.join(self.state, "guard.required.cluster")))
        dropin = open(os.path.join(self.t, "dropin", "zz-wazuh-migration-guard.conf")).read()
        self.assertIn("ExecStartPre=+/bin/bash %s reapply %s" % (os.path.join(self.t, "copy.sh"), self.state), dropin)   # E2-rpm fix 02: outside the unit sandbox
        self.assertEqual(self.g("status", "cluster", self.state)[1].strip(), "on")

    def test_reapply_after_a_reboot_puts_back_only_recorded_guards(self):
        self.g("on", "agent", self.state)
        os.remove(os.path.join(self.t, "ipt_MIGGUARD"))                 # the reboot
        rc, out = self.g("reapply", self.state)
        self.assertIn("agent guard RE-APPLIED", out)
        self.assertNotIn("cluster", out)
        self.assertEqual(self.g("status", "agent", self.state)[1].strip(), "on")

    def test_off_removes_the_drop_in_when_no_guard_is_left(self):
        self.g("on", "agent", self.state)
        self.g("on", "cluster", self.state)
        self.g("off", "agent", self.state)
        self.assertTrue(os.path.exists(os.path.join(self.t, "dropin", "zz-wazuh-migration-guard.conf")))
        self.g("off", "cluster", self.state)
        self.assertFalse(os.path.exists(os.path.join(self.t, "dropin", "zz-wazuh-migration-guard.conf")))

    def test_node_state_sees_the_merged_chains(self):
        self.g("on", "cluster", self.state)
        b = os.path.join(self.t, "bin")
        for c, body in (("rpm", 'echo "package $4 is not installed"'), ("dpkg-query", "exit 1"), ("pgrep", "exit 1"),
                        ("ss", "exit 0"), ("nft", "exit 1")):
            p = os.path.join(b, c)
            open(p, "w").write("#!/bin/bash\n%s\n" % body)
            os.chmod(p, 0o755)
        p = subprocess.run(["python3", os.path.join(SRC, "cluster", "node", "node-state.py"), "--bundle", self.t], env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode()
        self.assertIn('"k5-cluster-guard"', out)
        self.assertIn("DECISION: NO MANAGER", out)



class FleetMergeC10toC13(unittest.TestCase):
    def _st(self):
        return {"poll_interval": 900, "task_ttl": 3600, "agents": {}}

    def test_retry_list_clock_guards_a_new_request_A6(self):
        n = time.time()
        st = self._st()
        st["agents"]["005"] = {"requests": [{"t": n - 7000, "version": "v5.0.0", "first_push": n - 3000}]}
        a = types.SimpleNamespace(sweep_allowance=300)
        self.assertIsNotNone(FU.guard(st, "005", a, None))

    def test_states_from_both_arms_are_open_and_parked(self):
        for s in ("host-gone", "no-answer-stale", "no-answer"):
            self.assertIn(s, FU.OPEN)
            self.assertNotIn(s, FU.LANE_BUSY)
        self.assertIn("dropped", FU.TERMINAL_BAD)
        self.assertEqual(FU.TOOL_VERSION, "0.10-e3")   # E3 fold (0.9-e2 at the E2 fold)

    def test_refusal_line_of_a_silent_agent_is_read_A6(self):
        m = FU.RX["refused_stale"].search("2026/11/24 07:00:00 wazuh-manager-remoted: ERROR: req_send_and_wait(): cannot send request to agent '017'")
        self.assertEqual(m.group(1), "017")

    def test_cycles_from_push_lines_one_implementation_A6_D7(self):
        st = {}
        FU.record_cycles(st, [1000, 0, 100, 200, 1100])
        self.assertEqual((st["longest_cycle"], st["thread_busy_until"]), (200 + FU.RESPONSE_TIMEOUT, 1100))
        src = open(os.path.join(SRC, "fleet-upgrade.py")).read()
        self.assertEqual(src.count('st["longest_cycle"] = max('), 1)
        self.assertIn('if not st.get("busy_note"):', src)       # the busy line has its own note (A6-D7, merge)

    def test_batch_is_never_requested_while_the_delivery_thread_is_busy(self):
        src = open(os.path.join(SRC, "fleet-upgrade.py")).read()
        self.assertIn("thread_busy = now() - st.get(\"thread_busy_until\", 0) < RESPONSE_TIMEOUT + 60", src)
        self.assertIn("if s[\"state\"] in LANE_BUSY and not is_canary(i_)", src)


SAMPLE = """<ossec_config>
  <client>
    <server>
      <address>10.0.0.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu24</config-profile>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <authorization_pass_path>etc/authd.pass</authorization_pass_path>
    </enrollment>
  </client>
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
  </syscheck>
</ossec_config>
"""


class AgentConfAG1MAC1(unittest.TestCase):
    def test_python_and_sh_converters_give_the_same_file(self):
        d = tempfile.mkdtemp()
        try:
            src = os.path.join(d, "ossec.conf")
            open(src, "w").write(SAMPLE)
            r1 = subprocess.run(["python3", os.path.join(SRC, "agent", "agent-conf-5x.py"), "--file", src, "--out", os.path.join(d, "py.conf"),
                                 "--assume-5x"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            r2 = subprocess.run(["sh", os.path.join(SRC, "agent", "agent-conf-5x.sh"), "--file", src, "--out", os.path.join(d, "sh.conf"),
                                 "--assume-5x"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual((r1.returncode, r2.returncode), (0, 0), r1.stdout.decode() + r2.stdout.decode())
            py, sh = open(os.path.join(d, "py.conf")).read(), open(os.path.join(d, "sh.conf")).read()
            self.assertEqual(py, sh)
            self.assertIn("<notify_time>20</notify_time>", py)
            self.assertIn("<config-profile>ubuntu, ubuntu24</config-profile>", py)
            self.assertNotIn("<client>", py)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ConverterC4(unittest.TestCase):
    def test_the_converters_own_tests_pass(self):
        p = subprocess.run(["python3", "-m", "unittest", "discover", "-s", "tests", "-t", "."], cwd=os.path.join(SRC, "converter"),
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode()
        self.assertEqual(p.returncode, 0, out[-2000:])
        self.assertIn("Ran 230 tests", out)


if __name__ == "__main__":
    unittest.main()
