"""The fold of the three end-to-end runs (E2-rpm, E2-deb, E2-cluster) into src/, and the gaps they named that were
closed without a lab."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import tokenize
import types
import unittest
from unittest import mock

import helpers

SRC = helpers.SRC
MIGRATE = os.path.join(SRC, 'migrate.sh')

H = helpers.load(os.path.join(SRC, "mig_helper.py"), "e2_mig_helper")
IS = helpers.load(os.path.join(SRC, "identity_stage.py"), "e2_identity_stage")
SS = helpers.load(os.path.join(SRC, "settings_stage.py"), "e2_settings_stage")
FU = helpers.load(os.path.join(SRC, "fleet-upgrade.py"), "e2_fleet_upgrade")
BS = helpers.load(os.path.join(SRC, "bundle_secrets.py"), "e2_bundle_secrets")

CONF4 = "<agent_config>\n  <syscheck>\n    <prefilter_cmd>/usr/sbin/prelink -y</prefilter_cmd>\n  </syscheck>\n</agent_config>\n"
CLEANED = "<agent_config>\n  <syscheck>\n  </syscheck>\n</agent_config>\n"


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


# ------------------------------------------------------------------------------------------------ E2-rpm fix 01
def pep701_fstrings(path):
    """f-strings only Python 3.12 parses (PEP 701): a quote inside a replacement field that closes the enclosing literal
    on 3.8 to 3.11. ast.parse(feature_version=(3, 8)) on 3.12 accepts them, which is how indexer_stage.py line 144
    passed the merge's 3.8 check and failed on RHEL 9's Python 3.9."""
    if not hasattr(tokenize, "FSTRING_START"):
        return []           # before 3.12 the parser itself refuses them
    bad, stack = [], []

    def quote(s):
        s = s.lstrip("rRbBuUfF")
        return s[:3] if s[:3] in ('"""', "'''") else s[:1]
    with open(path) as f:
        for tok in tokenize.generate_tokens(f.readline):
            if tok.type == tokenize.FSTRING_START:
                q = quote(tok.string)
                if stack and q.startswith(stack[-1]):
                    bad.append("%s:%d" % (path, tok.start[0]))
                stack.append(q)
            elif tok.type == tokenize.FSTRING_END:
                stack.pop()
            elif tok.type == tokenize.STRING and stack and quote(tok.string).startswith(stack[-1]):
                bad.append("%s:%d" % (path, tok.start[0]))
    return bad


def py_files(root):
    return [os.path.join(r, f) for r, _, fs in os.walk(root) for f in fs if f.endswith(".py")]


class PythonFloorRpm01(unittest.TestCase):
    def test_no_312_only_fstring_anywhere_in_src(self):
        self.assertEqual([b for p in py_files(SRC) for b in pep701_fstrings(p)], [])



# ------------------------------------------------------------------------------------------------ E2-rpm fix 02, gap 7
class GuardDropInRpm02(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        b = os.path.join(self.t, "bin")
        os.makedirs(b)
        write(os.path.join(b, "iptables"), '#!/bin/bash\nf=%s/ipt_${@: -1}\ncase "$1" in -C) [ -e "$f" ];; -I) touch "$f";; -D) rm -f "$f";; esac\n' % self.t)
        for c in ("systemctl", "restorecon"):
            write(os.path.join(b, c), "#!/bin/sh\nexit 0\n")
        for c in os.listdir(b):
            os.chmod(os.path.join(b, c), 0o755)
        self.copy = os.path.join(self.t, "copy.sh")
        self.env = dict(os.environ, PATH=b + ":" + os.environ["PATH"], MIG_GUARD_DROPIN_DIR=os.path.join(self.t, "dropin"), MIG_GUARD_COPY=self.copy)

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def g(self, tree, *args):
        return subprocess.run(["bash", os.path.join(tree, "guard.sh")] + list(args), env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()

    def dropin(self):
        return open(os.path.join(self.t, "dropin", "zz-wazuh-migration-guard.conf")).read()

    def test_the_reapply_runs_outside_the_unit_sandbox(self):
        self.g(SRC, "on", "agent", os.path.join(self.t, "st"))
        self.assertIn("ExecStartPre=+/bin/bash ", self.dropin())


    def test_the_copy_goes_with_the_last_guard(self):
        st = os.path.join(self.t, "st")
        self.g(SRC, "on", "agent", st)
        self.assertTrue(os.path.exists(self.copy))
        self.g(SRC, "off", "agent", st)
        self.assertFalse(os.path.exists(self.copy))



# ------------------------------------------------------------------------------------------------ E2-rpm fix 03
class MarkerAfterSyncRpm03(unittest.TestCase):
    SYNC = 'if [ -e "$BUNDLE_DIR/state/m1" ]; then echo "marker existed before sync" >> "$BUNDLE_DIR/../sync.log"; else echo synced >> "$BUNDLE_DIR/../sync.log"; fi'

    def _migrate(self, script):
        sh = helpers.Shell(script)
        try:
            sh.stub("sync", self.SYNC)
            rc, out = sh.run("mark m1")
            log = os.path.join(sh.tmp, "sync.log")
            return open(log).read() if os.path.exists(log) else "", os.path.exists(os.path.join(sh.bundle, "state", "m1"))
        finally:
            sh.close()

    def test_migrate_sh_syncs_before_the_marker(self):
        # E3 fold: the marker is now also written beside and renamed, with syncs after it (whole or absent); the first sync
        # still comes before the marker exists
        log, exists = self._migrate(MIGRATE)
        self.assertTrue(log.startswith("synced\n"), log)
        self.assertTrue(exists)


    def _node(self, tree):
        t = tempfile.mkdtemp()
        try:
            b = os.path.join(t, "bin")
            write(os.path.join(b, "sync"), "#!/bin/bash\n" + self.SYNC + "\n")
            os.chmod(os.path.join(b, "sync"), 0o755)
            env = dict(os.environ, PATH=b + ":" + os.environ["PATH"], BUNDLE_DIR=os.path.join(t, "bundle"))
            subprocess.run(["bash", "-c", "source %s; mark m1" % os.path.join(tree, "cluster", "node", "common.sh")], env=env, check=True)
            log = os.path.join(t, "sync.log")
            return open(log).read() if os.path.exists(log) else ""
        finally:
            shutil.rmtree(t, ignore_errors=True)

    def test_cluster_node_steps_sync_before_the_marker(self):
        self.assertTrue(self._node(SRC).startswith("synced\n"))       # E3 fold: more syncs after it, the first before it


# ------------------------------------------------------------------------------------------------ rpm 04-06 + deb 1-2
class _Compare(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.fp, self.t4, self.t5 = (os.path.join(self.d, x) for x in ("fingerprint", "truth4", "truth5"))
        self.c4 = write(os.path.join(self.d, "c4.conf"), CONF4)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def bundle(self, live5, saved_objects5=(), ledger=None, dirs=None):
        """fingerprint/truth4/truth5 for a compare; live5: {group: path of 5.0's agent.conf}; ledger: {group: file} the
        pass uploaded (settings/groups-pre/uploaded.json); dirs: {group: [file, ...]} E2-rpm's pre-upgrade-<g>-* layout."""
        for x in (self.fp, self.t4, self.t5):
            os.makedirs(x, exist_ok=True)
        dash = [{"type": "dashboard", "id": "acme-dashboard-payments"}]
        fp = {"agents.json": [], "client_keys.json": {}, "enrollment.json": {"authd_pass_sha256": "a", "authd_pass_bytes": 32},
              "indexer_security.json": {"internalusers": [], "roles": [], "rolesmapping": []}, "saved_objects.json": dash,
              "manager_settings.json": {"ossec_conf_blocks": ["syslog_output"], "local_internal_options": []}, "indices.json": {},
              "group_files.json": {g: {"agent.conf": H.norm_sha(self.c4)} for g in live5}}
        for k, v in fp.items():
            write(os.path.join(self.fp, k), json.dumps(v))
        write(os.path.join(self.t4, "api_security.json"), json.dumps({"users": [], "roles": [], "policies": [], "rules": []}))
        write(os.path.join(self.t5, "group_files.json"), json.dumps({g: {"agent.conf": H.norm_sha(p)} for g, p in live5.items()}))
        write(os.path.join(self.t5, "saved_objects.json"), json.dumps(list(saved_objects5)))
        write(os.path.join(self.t5, "enrollment.json"), json.dumps({"authd_pass_sha256": "a"}))
        gp = os.path.join(self.d, "settings", "groups-pre")
        if ledger:
            rec = {}
            for g, f in ledger.items():
                d = os.path.join(gp, "pre-upgrade-%s-abcd1234" % g)
                write(os.path.join(d, "agent.conf"), open(f).read())
                rec[g] = {"agent_conf": os.path.relpath(os.path.join(d, "agent.conf"), gp)}
            write(os.path.join(gp, "uploaded.json"), json.dumps(rec))
        for i, (g, files) in enumerate(sorted((dirs or {}).items())):
            for j, f in enumerate(files):
                d = os.path.join(gp, "pre-upgrade-%s-x%d%d" % (g, i, j))
                write(os.path.join(d, "agent.conf"), open(f).read())
                os.utime(os.path.join(d, "agent.conf"), (1000 + 10 * i + j, 1000 + 10 * i + j))

    def compare(self, mod=H, env=None):
        with mock.patch.dict(os.environ, env or {"HISTORY_PENDING": "0"}):
            return quiet(mod.compare, self.t4, self.fp, self.t5)

    def line(self, out, start):
        return next(l for l in out.splitlines() if l.startswith(start))


class ComparePhase8Rpm04to06Deb1to2(_Compare):
    def test_a_group_the_pre_upgrade_pass_cleaned_is_CLEANED_not_LOST(self):
        cleaned = write(os.path.join(self.d, "cleaned.conf"), CLEANED)
        self.bundle({"acme-audit": cleaned}, ledger={"acme-audit": cleaned})
        r, out = self.compare()
        self.assertIn("CLEANED", self.line(out, "group acme-audit: agent.conf"))


    def test_a_cleaned_group_changed_since_is_still_LOST(self):
        cleaned = write(os.path.join(self.d, "cleaned.conf"), CLEANED)
        other = write(os.path.join(self.d, "other.conf"), "<agent_config><labels/></agent_config>\n")
        self.bundle({"acme-audit": other}, ledger={"acme-audit": cleaned})
        r, out = self.compare()
        self.assertIn("LOST", self.line(out, "group acme-audit: agent.conf"))

    def test_exact_group_names_where_one_name_starts_another(self):
        """Reconciliation: the record has exact names. E2-rpm's glob pre-upgrade-<group>-* also matches the directory of
        a group named '<group>-...', took the newest one and reported the group LOST although 5.0 held its own output."""
        a = write(os.path.join(self.d, "acme.conf"), "<agent_config><localfile/></agent_config>\n")
        b = write(os.path.join(self.d, "acme-audit.conf"), CLEANED)
        self.bundle({"acme": a, "acme-audit": b}, ledger={"acme": a, "acme-audit": b}, dirs={"acme": [a], "acme-audit": [b]})
        r, out = self.compare()
        self.assertIn("CLEANED", self.line(out, "group acme: agent.conf"))
        self.assertIn("CLEANED", self.line(out, "group acme-audit: agent.conf"))

    def test_dashboards_are_PENDING_until_the_history_phase(self):
        self.bundle({})
        r, out = self.compare(env={"HISTORY_PENDING": "1"})
        self.assertIn("PENDING", self.line(out, "custom dashboards"))
        r, out = self.compare(env={"HISTORY_PENDING": "0"})
        self.assertIn("LOST", self.line(out, "custom dashboards"))


    def test_manager_settings_line_says_converted_when_the_settings_stage_ran(self):
        """E2-rpm gap 8, E2-deb G7: the line said NOT CARRIED although the settings stage carried them."""
        self.bundle({})
        r, out = self.compare(env={"HISTORY_PENDING": "0", "SETTINGS_CARRIED": "1"})
        self.assertIn("CONVERTED", self.line(out, "manager settings"))

    def test_the_flow_tells_compare_whether_settings_were_carried(self):
        txt = open(MIGRATE).read()
        self.assertEqual(txt.count("SETTINGS_CARRIED=$(settings_carried) python3 \"$HELPER\" compare"), 2)


class SettingsStageRecordsUploads(unittest.TestCase):
    def test_the_pass_records_what_it_uploaded_by_exact_name(self):
        t = tempfile.mkdtemp()
        try:
            shutil.copytree(os.path.join(os.path.dirname(__file__), "fixtures", "settings", "groups"), os.path.join(t, "groups4"))
            shared, work = os.path.join(t, "shared"), os.path.join(t, "w")
            for g in os.listdir(os.path.join(t, "groups4")):
                os.makedirs(os.path.join(shared, g))
            ups = []
            with mock.patch.object(SS, "upload_group_conf", lambda g, data: ups.append(g) or (200, {"error": 0})):
                rc, out = quiet(SS.main, ["groups", "--phase", "pre-upgrade", "--groups", os.path.join(t, "groups4"),
                                          "--decisions", os.path.join(t, "d.json"), "--work", work, "--shared", shared])
            self.assertEqual(rc, 0, out)
            rec = json.load(open(os.path.join(work, "uploaded.json")))
            self.assertEqual(sorted(rec), sorted(ups))           # every upload, and only uploads (default's file is not one)
            self.assertNotIn("default", rec)
            f = os.path.join(work, rec["c4-audit"]["agent_conf"])
            self.assertNotIn("prefilter_cmd", open(f).read())
            self.assertEqual(rec["c4-audit"]["sha256"], hashlib.sha256(open(f, "rb").read()).hexdigest())
        finally:
            shutil.rmtree(t, ignore_errors=True)


class IdentityStageExpectedConfRpm06Deb1(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.shared = os.path.join(self.t, "shared")
        self.m = {"groups": [{"name": "acme-audit", "agent_conf": CONF4}]}
        gp = os.path.join(self.t, "settings", "groups-pre")
        write(os.path.join(gp, "pre-upgrade-acme-audit-abcd1234", "agent.conf"), CLEANED)
        self.ledger = write(os.path.join(gp, "uploaded.json"), json.dumps({"acme-audit": {"agent_conf": "pre-upgrade-acme-audit-abcd1234/agent.conf"}}))

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def live(self, text):
        write(os.path.join(self.shared, "acme-audit", "agent.conf"), text)

    def compare(self, mod, **kw):
        with mock.patch.object(mod, "SHARED", self.shared), mock.patch.object(mod, "read_registry", lambda api: ({}, {"acme-audit"})), \
                mock.patch.object(mod, "registry_keys", lambda path=None: {}):
            return mod.compare(None, self.t, self.m, {}, {}, set(), **kw)[0]

    def test_verify_accepts_the_pass_output_and_names_it(self):
        self.live(CLEANED)
        d = self.compare(IS, expected=IS.load_expected(self.ledger))
        self.assertEqual((d["conf_differs"], d["conf_cleaned"]), ([], ["acme-audit"]))
        self.assertFalse(IS.repairable(d))

    def test_without_the_record_it_is_a_difference(self):
        self.live(CLEANED)
        self.assertEqual(self.compare(IS)["conf_differs"], ["acme-audit"])

    def _groups(self, mod, **kw):
        sent = []
        api = types.SimpleNamespace(call=lambda m, p, body=None, ctype=None, timeout=None: sent.append((m, p, body)) or (200, {"error": 0}))
        st = types.SimpleNamespace(journal=lambda **k: None)
        import collections
        with mock.patch.object(mod, "SHARED", self.shared):
            mod.do_groups(api, st, self.t, self.m, {"acme-audit"}, set(), collections.Counter(), **kw)
        return [b for m, p, b in sent if m == "PUT"]

    def test_a_repair_writes_the_pass_output_never_the_refused_option(self):
        self.live(CLEANED)
        self.assertEqual(self._groups(IS, expected=IS.load_expected(self.ledger)), [])      # already as expected: nothing
        self.live(CONF4)                                                                      # someone put the 4.x file back
        self.assertEqual(self._groups(IS, expected=IS.load_expected(self.ledger)), [CLEANED])


    def test_the_flow_passes_the_record_to_every_identity_call_after_the_pass(self):
        txt = open(MIGRATE).read()
        self.assertEqual(txt.count('--state "$BUNDLE_DIR/identity-stage" "${EXP[@]}"'), 3)
        self.assertIn('$(pwflag) --with-rbac "${EXP[@]}"', txt)     # E4-breaker fix 02: --with-password only with a source password


# ------------------------------------------------------------------------------------------------ E2-deb fix 3
class LoaderWorkersDieWithTheirParentDeb03(unittest.TestCase):
    CODE = r'''
import concurrent.futures, importlib.util, multiprocessing, os, sys
init = None
if sys.argv[1] != "none":
    sys.path.insert(0, os.path.dirname(sys.argv[1]))
    spec = importlib.util.spec_from_file_location("hl", sys.argv[1]); hl = importlib.util.module_from_spec(spec); spec.loader.exec_module(hl)
    init = hl._die_with_parent
ex = concurrent.futures.ProcessPoolExecutor(1, mp_context=multiprocessing.get_context("fork"), initializer=init)
open(sys.argv[2], "w").write(str(ex.submit(os.getpid).result()))
os.kill(os.getpid(), 9)                  # the loader's parent dies hard (the OOM killer, a crash, --stop-after-files)
'''

    def worker_after_parent_kill(self, arg):
        # no pipe to the child: an orphaned worker holding it is exactly what hung migrate.sh (E2-deb G3)
        with tempfile.NamedTemporaryFile("r", delete=False) as f:
            pidfile = f.name
        subprocess.run([sys.executable, "-c", self.CODE, arg, pidfile], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        pid = int(open(pidfile).read())
        os.unlink(pidfile)
        alive = True
        for _ in range(50):
            try:
                st = open("/proc/%d/status" % pid).read()
                alive = "\nState:\tZ" not in st
            except OSError:
                alive = False
            if not alive:
                break
            time.sleep(0.1)
        if alive:
            os.kill(pid, signal.SIGKILL)
        return alive

    def test_the_worker_dies_with_the_loader(self):
        self.assertFalse(self.worker_after_parent_kill(os.path.join(SRC, "history_load.py")))


    def test_the_loader_pool_uses_it(self):
        self.assertIn("initializer=_die_with_parent", open(os.path.join(SRC, "history_load.py")).read())


# ------------------------------------------------------------------------------------------------ E2-deb fix 4
class AgentsRerunDeb04(unittest.TestCase):
    def run_agents(self, script):
        sh = helpers.Shell(script)
        try:
            for m in ("confirm.no_return", "agents.preflight", "agents.run", "agents.trust", "agents.feed", "agents.gate"):
                sh.write("state/" + m, "x\n")
            rc, out = sh.run('step() { if done_ "$1"; then echo "SKIP $1"; else echo "RUN $1"; fi; }; noagents() { return 1; }; cmd_agents')
            return out
        finally:
            sh.close()

    def test_a_rerun_for_a_late_agent_runs_every_step(self):
        out = self.run_agents(MIGRATE)
        self.assertEqual(out.count("RUN agents."), 5, out)



# ------------------------------------------------------------------------------------------------ identity stage power cut
class IdentityStagePowerCut(unittest.TestCase):
    ORIGINAL = b"host: 0.0.0.0\nport: 55000\nhttps:\n  enabled: yes\n"

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.api_yaml = write(os.path.join(self.t, "api.yaml"), self.ORIGINAL)

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def patches(self, mod):
        return [mock.patch.object(mod, "API_YAML", self.api_yaml), mock.patch.object(mod, "restart_manager", lambda st, why: 0.0),
                mock.patch.object(mod, "log", lambda m: None)] + ([mock.patch.object(mod, "chown_like", lambda p, r: None)])

    def ctx(self, mod):
        st = contextlib.ExitStack()
        for p in self.patches(mod):
            st.enter_context(p)
        return st

    def test_state_and_saved_original_are_fsynced(self):
        with self.ctx(IS), mock.patch("os.fsync", wraps=os.fsync) as fs:
            st = IS.State(os.path.join(self.t, "st"))
            IS.raise_limit(st, 0)
        self.assertGreaterEqual(fs.call_count, 4)          # saved original, state, raised api.yaml, state again


    def _cut_after_raise(self, mod, emptied):
        """raise, then a power cut that empties `emptied` (paths under the state directory or 'api'): the run A picture."""
        with self.ctx(mod):
            st = mod.State(os.path.join(self.t, "st"))
            mod.raise_limit(st, 0)
        for e in emptied:
            open(self.api_yaml if e == "api" else os.path.join(self.t, "st", e), "w").close()
        return os.path.join(self.t, "st")

    def test_an_empty_saved_original_is_never_put_back(self):
        sd = self._cut_after_raise(IS, ["api.yaml.orig"])
        with self.ctx(IS):
            st = IS.State(sd)
            with self.assertRaises(SystemExit) as e:
                IS.put_back_yaml(st)
        self.assertIn("cannot be put back automatically", str(e.exception))
        self.assertTrue(open(self.api_yaml, "rb").read().startswith(IS.RAISED_MARK.encode()))   # left as it was, not emptied


    def test_a_damaged_original_with_an_unraised_live_file_is_saved_again(self):
        st_dir = os.path.join(self.t, "st")
        with self.ctx(IS):
            st = IS.State(st_dir)
            write(st.saved_yaml, b"")                     # the cut came before the raise reached the disk
            st.data["limit"] = {"saved_sha": "x"}
            IS.check_saved_original(st)
        self.assertEqual(open(os.path.join(st_dir, "api.yaml.orig"), "rb").read(), self.ORIGINAL)

    def test_the_raise_is_built_from_the_saved_original_not_an_emptied_live_file(self):
        sd = self._cut_after_raise(IS, ["api"])
        with self.ctx(IS):
            IS.raise_limit(IS.State(sd), 0)
        self.assertIn(b"port: 55000", open(self.api_yaml, "rb").read())


    def test_an_emptied_state_file_is_set_aside_not_a_traceback(self):
        sd = self._cut_after_raise(IS, ["state.json"])
        with self.ctx(IS):
            st = IS.State(sd)
        self.assertIn("damaged_state", st.data)
        pre = os.path.join(self.t, "st-pre")
        write(os.path.join(pre, "state.json"), "")


class ImportGateComparesTheBytes(unittest.TestCase):
    def gate(self, script):
        sh = helpers.Shell(script)
        try:
            sh.write("identity-noagents/MANIFEST", "x")
            sh.write("identity-stage/state.json", "")            # emptied by a power cut
            sh.write("identity-stage/api.yaml.orig", "host: 0.0.0.0\n")
            sh.write("var/wazuh-manager/api/configuration/api.yaml", IS.RAISED_MARK + "\naccess:\n  max_request_per_minute: 0\n", base=sh.root)
            return sh.run("im_gate")
        finally:
            sh.close()

    def test_a_raised_api_yaml_is_refused_even_without_a_readable_state(self):
        rc, out = self.gate(MIGRATE)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("is not the original", out)



# ------------------------------------------------------------------------------------------------ E2-deb G11
class GoingBackKeepsNoSecretG11(unittest.TestCase):
    PW = "S3cr3t.Pw+AdminReinstall"

    def shell(self, script):
        sh = helpers.Shell(script)
        for c in ("systemctl", "sleep", "curl"):
            sh.stub(c)
        sh.stub("dpkg-query", "exit 1")
        sh.stub("rpm", "exit 1")
        return sh

    def install4(self, script):
        sh = self.shell(script)
        try:
            sh.write("v4/wazuh-install.sh", "readonly wazuh_version=\"4.14.11\"\necho 'INFO: The filebeat.yml file has been updated to use the Filebeat Keystore username and password.'\n"
                                             "echo 'INFO: You can access the web interface https://<wazuh-dashboard-ip>:443'\n"
                                             "echo '    User: admin'\necho '    Password: %s'\ntouch wazuh-install-files.tar\n" % self.PW)
            rc, out = sh.run('pkglist > "$BUNDLE_DIR/v4/packages.txt"; bk_install4')
            return rc, out, open(os.path.join(sh.bundle, "logs", "back-install-4x.log")).read()
        finally:
            sh.close()

    def test_the_reinstall_log_is_masked_as_written(self):
        rc, out, log = self.install4(MIGRATE)
        self.assertEqual(rc, 0, out)
        self.assertNotIn(self.PW, log)
        self.assertIn("Password: MASKED", log)
        self.assertIn("Keystore username and password.", log)         # prose about passwords is kept


    def test_going_back_ends_with_the_secret_cleanup(self):
        txt = open(MIGRATE).read()
        i, j, k = txt.index('step back.verify '), txt.index('step back.secrets '), txt.index('mark back.done')
        self.assertLess(i, j)
        self.assertLess(j, k)

    def test_bk_secrets_deletes_the_reinstall_output_and_the_bundle_secrets(self):
        sh = self.shell(MIGRATE)
        try:
            key = "0123456789abcdef0123456789abcdef"
            sh.write("v4/etc/client.keys", "001 ag1 any %s\n" % key)
            sh.write("v4/rollback/x", "y")
            work = os.path.join(sh.tmp, "work")
            write(os.path.join(work, "v4-install", "wazuh-install-files.tar"), "reinstall credentials")
            rc, out = sh.run("bk_secrets", env={"MIG_BUNDLE_ROOTS": sh.tmp})
            self.assertEqual(rc, 0, out)
            self.assertFalse(os.path.exists(os.path.join(work, "v4-install")))
            self.assertFalse(os.path.exists(os.path.join(sh.bundle, "v4", "etc")))
            self.assertIn("secret values this bundle carried: 1", out)
        finally:
            sh.close()

    def discard(self, markers):
        sh = self.shell(MIGRATE)
        try:
            for m in markers:
                sh.write("state/" + m, "x\n")
            sh.write("v4/etc/client.keys", "001 ag1 any 0123456789abcdef0123456789abcdef\n")
            sh.stub("pgrep", "exit 1")
            rc, out = sh.run('step() { "$3"; }; cmd_discard', env={"MIG_BUNDLE_ROOTS": sh.tmp})
            return rc, out, os.path.exists(os.path.join(sh.bundle, "state", "discarded")), os.path.exists(os.path.join(sh.bundle, "v4", "etc"))
        finally:
            sh.close()

    def test_discard_refuses_a_bundle_that_is_the_way_back(self):
        rc, out, discarded, kept = self.discard(["replace.remove4x"])
        self.assertNotEqual(rc, 0)
        self.assertIn("this bundle is the way back", out)
        self.assertEqual((discarded, kept), (False, True))

    def test_discard_cleans_a_bundle_abandoned_before_the_removal(self):
        rc, out, discarded, kept = self.discard(["phase.freeze"])
        self.assertEqual(rc, 0, out)
        self.assertEqual((discarded, kept), (True, False))

    def test_a_discarded_bundle_is_never_run_again(self):
        txt = open(MIGRATE).read()
        self.assertIn('[ ! -e "$STATE/discarded" ] || die "this bundle was discarded', txt)


class BundleSecretsSweep(unittest.TestCase):
    KEY = "0123456789abcdef0123456789abcdef01234567"

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.b = os.path.join(self.t, "bundle")
        write(os.path.join(self.b, "v4", "etc", "client.keys"), "001 ag1 any %s\n" % self.KEY)
        os.makedirs(os.path.join(self.b, "state"))
        self.work = os.path.join(self.t, "work")
        os.makedirs(self.work)

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def tgz(self, path, members):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with tarfile.open(path, "w:gz") as t:
            for name, data in members.items():
                i = tarfile.TarInfo(name)
                i.size = len(data)
                t.addfile(i, io.BytesIO(data))

    def sweep(self, **kw):
        return quiet(BS.sweep, self.b, [self.work], (), False, [self.t], **kw)

    def test_a_carried_value_inside_an_archive_is_found(self):
        """E2-rpm gap 5: values inside a gzip archive were not seen by the raw search."""
        self.tgz(os.path.join(self.b, "logs", "evidence.tar.gz"), {"x/log.txt": ("key %s\n" % self.KEY).encode()})
        rc, out = self.sweep()
        self.assertEqual(rc, 1, out)
        self.assertIn("key of agent 001 in %s:x/log.txt" % os.path.join(self.b, "logs", "evidence.tar.gz"), out)


    def test_an_installer_credentials_archive_in_the_work_directory_is_named_not_failed(self):
        self.tgz(os.path.join(self.work, "v5-install", "wazuh-install-files.tar"),
                 {"wazuh-install-files/wazuh-passwords.txt": b"x", "wazuh-install-files/admin-key.pem": b"-----BEGIN PRIVATE KEY-----\n"})
        rc, out = self.sweep()
        self.assertEqual(rc, 0, out)
        self.assertIn("v5-install/wazuh-install-files.tar (holds installer credentials", out)

    def test_cluster_bundle_values_are_read_from_the_rollback_archive(self):
        shutil.rmtree(os.path.join(self.b, "v4", "etc"))
        self.tgz(os.path.join(self.b, "v4", "rollback", "var-ossec.tar.gz"),
                 {"var/ossec/etc/client.keys": ("002 ag2 any %s\n" % self.KEY).encode(),
                  "var/ossec/etc/ossec.conf": b"<ossec_config><cluster><key>2123456789abcdef0123456789abcdef</key></cluster></ossec_config>",
                  "var/ossec/etc/authd.pass": b"enrollment-password-28-bytes\n"})
        vals = BS.carried_values(self.b)
        self.assertEqual(sorted(vals), ["4.x cluster key", "enrollment password", "key of agent 002"])

    def test_the_identity_stage_state_is_not_another_bundle(self):
        """E2-deb G7: the identity stage keeps its own journal.ndjson; it was named as another migration bundle."""
        write(os.path.join(self.b, "identity-stage", "journal.ndjson"), "{}\n")
        os.makedirs(os.path.join(self.b, "identity-stage", "state"))
        other = os.path.join(self.t, "bundle-a")
        write(os.path.join(other, "journal.ndjson"), "{}\n")
        os.makedirs(os.path.join(other, "state"))
        self.assertEqual(BS.other_bundles(self.b, [self.t]), [os.path.realpath(other)])


# ------------------------------------------------------------------------------------------------ E2-deb G8 (rule 14)
class FeedCompletionLineDebG8(unittest.TestCase):
    LINES = ["2026/11/24 11:06:01 wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: Consumer 'x' is ready. Starting feed download.",
             "2026/11/24 11:13:55 wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: Initial load download phase complete — 424972 documents, cursor: '1346239'",
             "2026/11/24 11:13:55 wazuh-manager-modulesd:vulnerability-scanner: INFO: CVE feed fully loaded — per-agent scans unblocked."]

    def test_the_completion_line_is_complete(self):
        t = time.mktime(time.strptime("2026/11/24 11:14:00", "%Y/%m/%d %H:%M:%S"))
        self.assertEqual(H.feed_load_state(self.LINES, t), ("complete", "2026/11/24 11:13:55"))

    def test_a_download_after_the_completion_is_a_new_load(self):
        later = self.LINES + ["2026/11/24 12:00:00 wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: Consumer 'x' is ready. Starting feed download."]
        t = time.mktime(time.strptime("2026/11/24 12:00:30", "%Y/%m/%d %H:%M:%S"))
        self.assertEqual(H.feed_load_state(later, t)[0], "loading")



# ------------------------------------------------------------------------------------------------ rule 14: wait for the feed
class FeedWaitRule14(unittest.TestCase):
    START = "2026/11/24 11:06:01 wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: Consumer 'x' is ready. Starting feed download.\n"
    DONE = "2026/11/24 11:13:55 wazuh-manager-modulesd:vulnerability-scanner: INFO: CVE feed fully loaded — per-agent scans unblocked.\n"

    def setUp(self):
        self.d = tempfile.mkdtemp(); self.log = os.path.join(self.d, "wazuh-manager.log")
        self.conf = os.path.join(self.d, "wazuh-manager.conf")
        open(self.conf, "w").write("<ossec_config><vulnerability-detection>\n  <enabled>yes</enabled>\n</vulnerability-detection></ossec_config>")
        self.clock = [time.mktime(time.strptime("2026/11/24 11:07:00", "%Y/%m/%d %H:%M:%S"))]

    def _run(self, max_s, on_sleep=None):
        def sleep(s):
            self.clock[0] += s
            if on_sleep: on_sleep(self.clock[0])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            r = H.feed_wait(self.log, str(max_s), self.conf, "30", _now=lambda: self.clock[0], _sleep=sleep)
        return r, out.getvalue()

    def test_waits_until_the_completion_line(self):
        open(self.log, "w").write(self.START)
        t_done = self.clock[0] + 400
        def grow(now):
            if now >= t_done and self.DONE not in open(self.log).read():
                open(self.log, "a").write(self.DONE)
        r, out = self._run(3600, grow)
        self.assertEqual(r, 0, out)
        self.assertIn("complete", out)
        self.assertGreaterEqual(self.clock[0], t_done)

    def test_silence_is_not_completion(self):
        open(self.log, "w").write(self.START)          # progress stopped, no completion line: keeps waiting, then fails
        r, out = self._run(600)
        self.assertEqual(r, 1)
        self.assertIn("NOT LOADED after 600 s", out)
        self.assertIn("FEED_WAIT_MAX=0", out)

    def test_already_complete_returns_at_once(self):
        open(self.log, "w").write(self.START + self.DONE)
        t0 = self.clock[0]
        self.assertEqual(self._run(3600)[0], 0)
        self.assertEqual(self.clock[0], t0)

    def test_a_new_load_after_a_completion_is_waited_for(self):
        open(self.log, "w").write(self.START + self.DONE + self.START.replace("11:06:01", "11:20:00"))
        self.assertEqual(self._run(120)[0], 1)

    def test_vulnerability_detection_off_needs_no_feed(self):
        open(self.conf, "w").write("<ossec_config><vulnerability-detection>\n  <enabled>no</enabled>\n</vulnerability-detection></ossec_config>")
        r, out = self._run(60)
        self.assertEqual(r, 0)
        self.assertIn("vulnerability detection is off", out)

    def test_another_section_off_is_not_vulnerability_detection_off(self):
        open(self.conf, "w").write("<ossec_config><vulnerability-detection><enabled>yes</enabled></vulnerability-detection>"
                                   "<sca><enabled>no</enabled></sca></ossec_config>")
        open(self.log, "w").write(self.START)
        self.assertEqual(self._run(60)[0], 1)

    def test_the_flow_waits_in_phase_10_and_before_the_finish_restart(self):
        src = open(os.path.join(helpers.SRC, "migrate.sh")).read()
        self.assertIn('ag_feed() { feed_wait; }', src)
        fi = src[src.index("fi_legacy() {"):src.index("fi_agents_after()")]
        self.assertLess(fi.index("feed_wait || return 1"), fi.index("sed -i '/<legacy>/"))   # before the configuration is touched
        self.assertLess(fi.index("feed_wait || return 1"), fi.index("systemctl restart wazuh-manager"))
        node = open(os.path.join(helpers.SRC, "cluster", "node", "finish-node.sh")).read()
        lc = node[node.index("legacy-close)"):]
        self.assertLess(lc.index("feed-wait"), lc.index("systemctl restart wazuh-manager"))


# ------------------------------------------------------------------------------------------------ E2-cluster gap 5
class CertificatePreflightPerNodeClusterGap5(unittest.TestCase):
    NODES = {"wazuh-1": {"ip": "198.51.100.14"}, "wazuh-2": {"ip": "198.51.100.13"}}
    SANS = {"wazuh-1": ["198.51.100.14", "wazuh-1"], "wazuh-2": ["198.51.100.13", "wazuh-2"]}

    def test_a_node_address_reaches_only_that_node(self):
        self.assertEqual(FU.nodes_reached("198.51.100.14", self.NODES, resolve=False), ["wazuh-1"])
        self.assertEqual(FU.cert_missing("198.51.100.14", self.SANS, self.NODES, resolve=False), [])

    def test_a_balancer_name_reaches_every_node(self):
        self.assertEqual(FU.nodes_reached("lb.example", self.NODES, resolve=False), ["wazuh-1", "wazuh-2"])
        self.assertEqual(FU.cert_missing("lb.example", self.SANS, self.NODES, resolve=False), ["wazuh-1", "wazuh-2"])

    def test_a_per_node_name_given_by_the_user(self):
        na = FU.parse_node_addresses(["wazuh-2=mgr2.example"])
        self.assertEqual(FU.nodes_reached("mgr2.example", self.NODES, na, resolve=False), ["wazuh-2"])

    def _preflight(self, mod):
        node = lambda name: {"type": "master", "ip": self.NODES[name]["ip"], "poll_interval": 900, "task_manager": {},
                             "remote": {"legacy": {"enabled": True}, "https": {"bind_addr": "0.0.0.0", "port": 1517, "verification_mode": "none"}},
                             "tls": {"available": True, "listener": {"sans": self.SANS[name], "seconds_until_expiry": 10 ** 9},
                                     "ca_bundle": {"chain_valid": True, "matches_active_leaf": True}}}
        mf = {"version": "v5.0.0", "nodes": {n: node(n) for n in self.NODES}}
        ka = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
        agents = [{"id": "002", "name": "ag1", "version": "Wazuh v4.14.10", "status": "active", "lastKeepAlive": ka,
                   "os": {"platform": "ubuntu", "arch": "x86_64", "major": "24", "name": "Ubuntu", "version": "24.04"}}]
        facts = {"002": {"dialed": ["198.51.100.14"], "openssl": "3.0.13", "curl": "8.5"}}
        a = types.SimpleNamespace(target="v5.0.0", poll_interval=None, wpk_repo="repo", step_wpk_repo=None, agents=None, groups=None,
                                  package_type=None, step_version=None, include_stale=False, include_disconnected=False,
                                  allow_cert_mismatch=False, listener_host="h", api="https://localhost:55000", canary_key="platform",
                                  batch_size=50, macos_anchor_placed=False, node_address=None)
        with mock.patch.object(mod, "manager_facts", lambda api: mf), mock.patch.object(mod, "fleet", lambda api, *x: agents), \
                mock.patch.object(mod, "repo_has", lambda *x, **k: (True, "")), mock.patch.object(mod, "probe_listener", lambda *x: (True, "ok", "TLSv1.3")), \
                mock.patch.object(mod, "socket", types.SimpleNamespace(getaddrinfo=lambda *x: [], create_connection=None)):
            return mod.preflight(None, a, facts)["plan"]["002"]["skip"]

    def test_an_agent_dialling_its_own_node_is_not_skipped(self):
        self.assertIsNone(self._preflight(FU))



if __name__ == "__main__":
    unittest.main()
