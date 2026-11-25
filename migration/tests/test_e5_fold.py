"""The E5 fold: the three E5 runs (E5-aio, E5-cluster-rpm, E5-cluster-deb) folded into the
tool. Section A: the runs' own fixes, reconciled where both cluster runs fixed the same bug. Section B: the gaps the
runs found."""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

import helpers
from test_e2_cluster import NodeSteps, tgz, write

SRC = helpers.SRC


def bash(code, env=None, timeout=60):
    r = subprocess.run(["bash", "-c", code], env=dict(os.environ, **(env or {})), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return r.returncode, r.stdout.decode(errors="replace")


class _Node(unittest.TestCase):
    def node(self, tree=SRC, src=None):
        n = NodeSteps(tree, src)
        self.addCleanup(n.close)
        return n


# ================================================================================================ A1: v5cred
class V5credWithoutThe5xInstallFilesA1(_Node):
    """E5-cluster-deb 01 = E5-cluster-rpm 01 (the same one line): every node step that loads aio_lib with IDX5_HOST set
    died with exit 2 and no message on a node without the 5.0 install files (every node before phase 5)."""

    def read(self, tree):
        n = self.node(tree)
        code = '. %s; x=$(v5cred WAZUH_INDEXER_ADMIN_PASSWORD); echo "value [$x]"' % os.path.join(n.node, "common.sh")
        return bash(code, n.env)

    def test_the_value_is_empty_and_the_step_goes_on(self):
        rc, out = self.read(SRC)
        self.assertEqual(rc, 0, out)
        self.assertIn("value []", out)

    def test_a_value_present_is_still_read(self):
        n = self.node()
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w") as t:
            data = b'WAZUH_INDEXER_ADMIN_PASSWORD="not-a-real-one"\n'
            i = tarfile.TarInfo("wazuh-install-files/credentials.env")
            i.size = len(data)
            t.addfile(i, io.BytesIO(data))
        write(n.env["V5_TAR"], b.getvalue())
        rc, out = bash('. %s; x=$(v5cred WAZUH_INDEXER_ADMIN_PASSWORD); echo "value [$x]"' % os.path.join(n.node, "common.sh"), n.env)
        self.assertEqual(rc, 0, out)
        self.assertIn("value [not-a-real-one]", out)



# ================================================================================================ A2: assess on a cluster
from test_cl1_cluster import Cluster, FAKE_SSH  # noqa: E402

FAKE_SSH_HOSTS = FAKE_SSH.replace('if [ -n "${FAIL_PAT:-}" ] && [[ "$cmd" == *$FAIL_PAT* ]]; then',
                                  'if [ -n "${FAIL_PAT:-}" ] && [[ "$cmd" == *$FAIL_PAT* ]] && { [ -z "${FAIL_HOSTS:-}" ] || [[ " $FAIL_HOSTS " == *" $host "* ]]; }; then')
assert FAKE_SSH_HOSTS != FAKE_SSH


class _C(unittest.TestCase):
    def cluster(self, tree=SRC, **over):
        c = Cluster(tree, **over)
        write(os.path.join(c.t, "fakessh"), FAKE_SSH_HOSTS, 0o755)    # FAIL_HOSTS: only these nodes fail FAIL_PAT
        self.addCleanup(c.close)
        return c

    @staticmethod
    def first(calls, host, text):
        for k, x in enumerate(calls):
            if x.startswith(host + " ") and text in x:
                return k
        return None


class AssessOnAClusterA2(_C):
    """E5-cluster-deb 02 = E5-cluster-rpm 02: the master's cluster check read the 4.x API password from install files only
    the pre-copy staged (HTTP 401 at every first assess). E5-cluster-rpm 03 = E5-cluster-deb 03: assess runs on every
    'run' and refused the nodes this run had already moved to 5.0, so no run stopped after phase 5 could be resumed."""
    M = "10.0.0.11"
    MOVED = "10.0.0.1 10.0.0.2 10.0.0.21"

    def test_the_4x_install_files_reach_the_master_before_its_cluster_check(self):
        c = self.cluster()
        rc, out, calls = c.run("run", "--only", "assess")
        self.assertEqual(rc, 0, out[-2000:])
        staged = self.first(calls, self.M, "v4/wazuh-install-files.tar.part")
        check = self.first(calls, self.M, "source-version.sh cluster")
        self.assertIsNotNone(staged, calls)
        self.assertLess(staged, check)


    def moved_then_assess(self, tree):
        c = self.cluster(tree)
        rc, out, _ = c.run("run", "--through", "indexers")
        self.assertEqual(rc, 0, out[-2000:])
        return c.run("run", "--only", "assess", FAIL_PAT="source-version.sh", FAIL_HOSTS=self.MOVED)

    def test_a_rerun_after_the_indexers_skips_the_moved_nodes_and_checks_the_rest(self):
        rc, out, calls = self.moved_then_assess(SRC)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("node node-1: 4.x already removed by this run (indexers.remove4x at", out)
        for h in self.MOVED.split():
            self.assertIsNone(self.first(calls, h, "source-version.sh"), h)
        for h in ("10.0.0.11", "10.0.0.12"):                       # the managers are still 4.x: still checked
            self.assertIsNotNone(self.first(calls, h, "source-version.sh"), h)
        self.assertIsNotNone(self.first(calls, self.M, "source-version.sh cluster"))


    def test_after_the_masters_freeze_its_cluster_view_is_not_asked_again(self):
        c = self.cluster()
        rc, out, _ = c.run("run", "--through", "master")
        self.assertEqual(rc, 0, out[-2000:])
        rc, out, calls = c.run("run", "--only", "assess", FAIL_PAT="source-version.sh", FAIL_HOSTS=self.MOVED + " " + self.M)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIsNone(self.first(calls, self.M, "source-version.sh"))
        self.assertIn("the cluster view was checked before", out)
        self.assertIsNotNone(self.first(calls, "10.0.0.12", "source-version.sh"))


# ================================================================================================ A3: a step that ended alone
class AStepThatEndedAfterItsCallerA3(unittest.TestCase):
    """E5-cluster-rpm 04: the controller was SIGKILLed while master.install5 ran; the step finished alone (exit 0); the
    rerun found no live runner and started it a second time."""

    def setup(self, tree):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        shutil.copy(os.path.join(tree, "cluster", "node", "run-step.sh"), t)
        write(os.path.join(t, "demo.sh"), "#!/bin/bash\necho start $*; sleep 1; echo end; exit 0\n", 0o755)
        return t, dict(os.environ, BUNDLE_DIR=os.path.join(t, "b"), RUN_STEP_POLL="0.2")

    def killed_then_rerun_after_the_end(self, tree):
        t, env = self.setup(tree)
        p = subprocess.Popen(["bash", os.path.join(t, "run-step.sh"), "s1", "demo.sh", "a"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(0.5)
        p.kill()
        p.wait()
        rc_file = os.path.join(t, "b", "logs", "steps", "s1.rc")
        for _ in range(50):                                   # the detached step ends on its own
            if os.path.exists(rc_file):
                break
            time.sleep(0.1)
        time.sleep(0.2)
        r = subprocess.run(["bash", os.path.join(t, "run-step.sh"), "s1", "demo.sh", "a"], env=env, capture_output=True, text=True, timeout=30)
        log = open(os.path.join(t, "b", "logs", "steps", "s1.log")).read()
        return r, log, t

    def test_the_rerun_reports_its_exit_code_and_does_not_start_it_again(self):
        r, log, t = self.killed_then_rerun_after_the_end(SRC)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("finished on this node after the call that started it had ended: exit 0; not started again", r.stdout)
        self.assertIn("end", r.stdout)                         # its transcript is shown
        self.assertEqual(log.count("start a"), 1)
        self.assertFalse(os.path.exists(os.path.join(t, "b", "logs", "steps", "s1.pid")))   # collected now
        r2 = subprocess.run(["bash", os.path.join(t, "run-step.sh"), "s1", "demo.sh", "a"],
                            env=dict(os.environ, BUNDLE_DIR=os.path.join(t, "b"), RUN_STEP_POLL="0.2"), capture_output=True, text=True, timeout=30)
        self.assertEqual(open(os.path.join(t, "b", "logs", "steps", "s1.log")).read().count("start a"), 2)   # a collected step runs again



ASSISTANT5 = r"""#!/usr/bin/env bash
# a stand-in for the 5.0 assistant: the package "installed" is a file under $FAKE; refuses as the real one does
echo "assistant $*" >> "$FAKE/assistant.calls"
case "$1" in
  -wm) if [ -e "$FAKE/installed-wazuh-manager" ]; then echo "ERROR: Wazuh manager components are already installed. Use option -o"; exit 1; fi
       echo "5.0.0-1" > "$FAKE/installed-wazuh-manager"
       [ -z "${FAIL_AFTER_PKG:-}" ] || { echo "ERROR: wazuh-manager could not be started"; exit 1; }
       echo "INFO: Installation finished";;
  -g)  if [ -e wazuh-install-files.tar ]; then echo "ERROR: File $PWD/wazuh-install-files.tar already exists"; exit 1; fi
       echo "generated $(date +%s%N)" > wazuh-install-files.tar; mkdir -p wazuh-ca; echo "fake ca key" > wazuh-ca/root-ca.key
       [ -z "${FAIL_G:-}" ] || { echo "ERROR: -g failed half way"; exit 1; }
       echo "INFO: Configuration files created";;
esac
exit 0
"""


class Install5DecidesFromTheNodeA3(_Node):
    """E5-cluster-rpm 05 = E5-cluster-deb 04: install5.sh ran the 5.0 assistant again on an installed component. Deb 08: a
    second migration in the same work_dir failed at -g on the first one's files. Both with a success-only marker (deb's
    first version trusted T_install5*_end, written on failure too; rpm's trusted an earlier "Installation finished" log)."""

    def setup(self, tree):
        n = self.node(tree)
        fake = os.path.join(n.t, "fake")
        os.makedirs(fake)
        n.env["FAKE"] = fake
        n.stub("rpm", 'if [ "$1" = -q ] && [ -e "%s/installed-${@: -1}" ]; then cat "%s/installed-${@: -1}"; else echo "package ${@: -1} is not installed"; exit 1; fi' % (fake, fake))
        n.stub("shred", 'for a in "$@"; do [ "$a" = -u ] || rm -f "$a"; done')
        v5 = os.path.join(n.env["MIG_HOME"], "v5")
        write(os.path.join(v5, "wazuh-install.sh"), ASSISTANT5, 0o755)
        write(os.path.join(v5, "config.yml"), "nodes: {}\n")
        write(n.env["V5_TAR"], "5.0 install files (fake)\n")
        return n

    def calls(self, n):
        p = os.path.join(n.env["FAKE"], "assistant.calls")
        return open(p).read().splitlines() if os.path.exists(p) else []

    def test_a_rerun_after_a_success_does_not_run_the_assistant_again(self):
        n = self.setup(SRC)
        self.assertEqual(n.run("install5.sh", "-wm", "wazuh-1")[0], 0)
        rc, out = n.run("install5.sh", "-wm", "wazuh-1")
        self.assertEqual(rc, 0, out)
        self.assertIn("was installed here by this step at", out)
        self.assertEqual(len(self.calls(n)), 1)


    def earlier_success_then_a_failed_attempt(self, tree):
        n = self.setup(tree)
        self.assertEqual(n.run("install5.sh", "-wm", "wazuh-1")[0], 0)
        os.unlink(os.path.join(n.env["FAKE"], "installed-wazuh-manager"))      # 5.0 removed (a way back), the bundle kept
        time.sleep(1.1)                                                          # the assistant log names carry the second
        rc, out = n.run("install5.sh", "-wm", "wazuh-1", env={"FAIL_AFTER_PKG": "1"})   # fails after its package went in
        self.assertNotEqual(rc, 0, out)
        time.sleep(1.1)
        return n, n.run("install5.sh", "-wm", "wazuh-1")

    def test_an_earlier_success_does_not_stand_for_a_later_failed_install(self):
        n, (rc, out) = self.earlier_success_then_a_failed_attempt(SRC)
        self.assertNotIn("was installed here by this step", out)
        self.assertNotEqual(rc, 0)                       # the assistant ran and refused: the failure is not hidden
        self.assertEqual(len(self.calls(n)), 3)
        self.assertFalse(os.path.exists(os.path.join(n.bundle, "state", "install5-wm.ok")))


    def second_bundle_g(self, tree):
        n = self.setup(tree)
        self.assertEqual(n.run("install5.sh", "-g")[0], 0)                       # bundle A's -g
        b = os.path.join(n.t, "bundle-b")
        return n, b, n.run("install5.sh", "-g", env={"BUNDLE_DIR": b})           # bundle B, the same work_dir

    def test_a_second_migration_in_the_same_work_dir_generates_anew(self):
        n, b, (rc, out) = self.second_bundle_g(SRC)
        self.assertEqual(rc, 0, out)
        self.assertIn("an earlier attempt's 5.0 install files are in", out)
        self.assertEqual(len([c for c in self.calls(n) if c.startswith("assistant -g")]), 2)
        self.assertTrue(os.path.exists(os.path.join(b, "state", "install5-g.ok")))


    def test_a_failed_g_leaves_no_marker_and_the_rerun_generates_again(self):
        n = self.setup(SRC)
        rc, out = n.run("install5.sh", "-g", env={"FAIL_G": "1"})
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(os.path.join(n.bundle, "state", "install5-g.ok")))
        self.assertTrue(os.path.exists(os.path.join(n.bundle, "state", "T_install5-g_end")))   # written on failure too
        rc, out = n.run("install5.sh", "-g")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("not generated again", out)
        self.assertEqual(len([c for c in self.calls(n) if c.startswith("assistant -g")]), 2)
        rc, out = n.run("install5.sh", "-g")                                         # now it succeeded: not again
        self.assertIn("not generated again", out)
        self.assertEqual(len([c for c in self.calls(n) if c.startswith("assistant -g")]), 2)


# ================================================================================================ A4: settings answers
FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "settings")
CONV = os.path.join(SRC, "converter")
STOCK = os.path.join(CONV, "refs", "stock-4.14.10-ubuntu24")
AIO_BASE = os.path.join(CONV, "refs", "base-5.0.0-aio")
NODE_NAME = "ossec.conf:/ossec_config[1]/cluster[1]/node_name[1]"
TOPOLOGY = "ossec.conf:/$topology/mismatch"


def cluster_v4(dst, node_name="wazuh-1", node_type="master"):
    """The e1x-aio 4.x files as a node of a two-manager cluster (cluster enabled, a real master address)."""
    shutil.copytree(os.path.join(FX, "e1x-aio"), dst)
    os.unlink(os.path.join(dst, "decisions.json"))
    p = os.path.join(dst, "ossec.conf")
    t = open(p).read()
    t = t.replace("<node_name>node01</node_name>", "<node_name>%s</node_name>" % node_name).replace("<node_type>master</node_type>", "<node_type>%s</node_type>" % node_type)
    t = t.replace("<key></key>", "<key>" + "a1b2c3d4" * 4 + "</key>").replace("<node>NODE_IP</node>", "<node>10.0.0.11</node>")
    t = t.replace("<disabled>yes</disabled>\n  </cluster>", "<disabled>no</disabled>\n  </cluster>")
    open(p, "w").write(t)
    return dst


def installed_cluster_base(dst, node_name="wazuh-1", node_type="master"):
    """What the 5.0 install writes on a cluster node (by hand here: the shipped base with its <cluster> rewritten)."""
    shutil.copytree(AIO_BASE, dst)
    p = os.path.join(dst, "wazuh-manager.conf")
    t = open(p).read()
    t = t.replace("<node_name>node01</node_name>", "<node_name>%s</node_name>" % node_name).replace("<node_type>master</node_type>", "<node_type>%s</node_type>" % node_type)
    t = t.replace("<bind_addr>127.0.0.1</bind_addr>", "<bind_addr>0.0.0.0</bind_addr>").replace("<node>127.0.0.1</node>", "<node>10.0.0.11</node>")
    open(p, "w").write(t)
    return dst


class SettingsAnswersForQuestionsNoLongerAskedA4(unittest.TestCase):
    """E5-cluster-deb 05 = E5-cluster-rpm 07: the master's plan against its installed base stopped on "1 question open:
    cluster/node_name" although the installed node_name equals 4.x's: the pre-copy's answer was sent again, refused
    ("Unused decision ids"), the entry reopened, and no answer could close it (the master's listeners stayed closed)."""

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="e5-settings-")
        self.addCleanup(shutil.rmtree, self.t, True)
        self.v4 = cluster_v4(os.path.join(self.t, "v4"))
        self.groups = os.path.join(self.t, "groups4")
        shutil.copytree(os.path.join(FX, "groups"), self.groups)
        self.dec = os.path.join(self.t, "decisions.json")
        self.answers = json.load(open(os.path.join(FX, "e1x-aio", "decisions.json")))

    def plan(self, ss, base, label):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ss.main(["plan", "--v4", self.v4, "--stock", STOCK, "--base", base, "--decisions", self.dec,
                          "--work", os.path.join(self.t, "work-" + label), "--groups", self.groups])
        return rc, buf.getvalue()

    def precopy_answered(self, ss):
        rc, out = self.plan(ss, AIO_BASE, "pre")
        self.assertEqual(rc, 3, out)
        d = json.load(open(self.dec))
        self.assertIn(NODE_NAME, list(d["settings"]))             # the shipped (all-in-one) base asks these two
        self.assertIn(TOPOLOGY, list(d["settings"]))
        d["settings"].update(self.answers)
        d["settings"][NODE_NAME].update({"action": "keep", "reason": "this is wazuh-1's own file"})
        d["settings"][TOPOLOGY].update({"action": "keep", "reason": "the 5.0 node is a cluster node"})
        json.dump(d, open(self.dec, "w"))

    def ss(self, tree):
        return helpers.load(os.path.join(tree, "settings_stage.py"), "e5_ss_%d" % abs(hash(tree)))

    def test_the_installed_plan_passes_with_the_precopy_answers_held_back(self):
        ss = self.ss(SRC)
        self.precopy_answered(ss)
        rc, out = self.plan(ss, installed_cluster_base(os.path.join(self.t, "base-inst")), "inst")
        self.assertEqual(rc, 0, out)
        d = json.load(open(self.dec))
        self.assertEqual(d["settings"][NODE_NAME]["action"], "keep")            # kept in the file, unused
        self.assertNotIn("refused", d["settings"][NODE_NAME])


    def test_a_question_the_installed_plan_does_ask_still_closes_with_its_answer(self):
        ss = self.ss(SRC)
        self.precopy_answered(ss)
        d = json.load(open(self.dec))
        d["settings"][NODE_NAME].update({"action": "omit", "reason": "the 5.0 node keeps its installed name"})
        json.dump(d, open(self.dec, "w"))
        rc, out = self.plan(ss, installed_cluster_base(os.path.join(self.t, "base-other"), node_name="wazuh-9"), "other")
        self.assertEqual(rc, 0, out)                                             # asked (wrong node), answered, closed
        self.assertNotIn("refused", json.load(open(self.dec))["settings"][NODE_NAME])
        d["settings"][NODE_NAME].update({"action": None})
        json.dump(d, open(self.dec, "w"))
        rc, out = self.plan(ss, installed_cluster_base(os.path.join(self.t, "base-other2"), node_name="wazuh-9"), "other2")
        self.assertEqual(rc, 3, out)                                             # and without an answer it stays open

    def stale_open_entry(self, tree):
        ss = self.ss(tree)
        self.precopy_answered(ss)
        d = json.load(open(self.dec))
        d["settings"][NODE_NAME].update({"action": None, "refused": {"why": "an older tool's loop"}})
        json.dump(d, open(self.dec, "w"))
        return self.plan(ss, installed_cluster_base(os.path.join(self.t, "base-inst")), "inst")

    def test_an_open_entry_this_run_does_not_ask_does_not_stop_it(self):
        rc, out = self.stale_open_entry(SRC)
        self.assertEqual(rc, 0, out)



# ================================================================================================ A5: agents-node.sh raw
ARGV_PRINTER = "import json, sys\nprint('ARGV ' + json.dumps(sys.argv[1:]))\n"


def fake_src(tree, t, **replace):
    """A copy of a tree's src/ with some files replaced (a stand-in program), for a node step that calls them."""
    d = os.path.join(t, "fsrc")
    shutil.copytree(tree, d, ignore=shutil.ignore_patterns("__pycache__"))
    for name, text in replace.items():
        write(os.path.join(d, name.replace("__", "/")), text)
    return d


class AgentsRawPassesItsCommandOnceA5(_Node):
    """E5-cluster-rpm 08 = E5-cluster-deb 09: finish.legacy -> legacy-decide -> fleet-upgrade.sh legacy-status ->
    agents-node.sh raw legacy-status failed with "unrecognized arguments: legacy-status": the cluster finish never ran."""

    def argv(self, tree, env=None):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        n = self.node(tree, fake_src(tree, t, **{"fleet-upgrade.py": ARGV_PRINTER}))
        rc, out = n.run("agents-node.sh", "raw", "legacy-status", env=env)
        m = re.search(r"^ARGV (.*)$", out, re.M)
        self.assertIsNotNone(m, out)
        return json.loads(m.group(1))

    def test_the_command_goes_once_with_the_connection(self):
        a = self.argv(SRC, {"LISTENER_HOST": "mgr1.example"})
        self.assertEqual(a.count("legacy-status"), 1)
        self.assertEqual(a[0], "legacy-status")
        self.assertIn("--api", a)
        self.assertEqual(a[a.index("--listener-host") + 1], "mgr1.example")



# ================================================================================================ A6: decisions.json
class DecisionsFileOutOfTheManifestA6(_Node):
    """E5-cluster-deb 06: the master's MANIFEST.sha256 (written at its export) covered decisions.json, which the command
    rewrites around every step that can ask; the whole-cluster way back then refused the master (after the other nodes
    had removed 5.0)."""

    def bundle(self, n):
        write(os.path.join(n.bundle, "v4", "etc", "ossec.conf"), "<ossec_config/>\n")
        write(os.path.join(n.bundle, "decisions.json"), '{"settings": {}}\n')
        subprocess.run("cd %s && find . -type f ! -path './state/*' ! -path './logs/*' ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256" % n.bundle,
                       shell=True, check=True)                       # a manifest as the export wrote it before this fold
        write(os.path.join(n.bundle, "decisions.json"), '{"settings": {"x": {"action": "omit", "reason": "asked later"}}}\n')

    def test_a_later_answer_does_not_fail_the_bundle_check(self):
        n = self.node()
        self.bundle(n)
        rc, out = n.run("bundle-check.sh", "manifest")
        self.assertEqual(rc, 0, out)

    def test_a_changed_bundle_file_still_fails(self):
        n = self.node()
        self.bundle(n)
        write(os.path.join(n.bundle, "v4", "etc", "ossec.conf"), "<ossec_config>changed</ossec_config>\n")
        rc, out = n.run("bundle-check.sh", "manifest")
        self.assertNotEqual(rc, 0)
        self.assertIn("does not match its manifest", out)


    def test_every_check_and_the_export_leave_the_decisions_file_out(self):
        for f in ("remove4x.sh", "goback-remove5.sh", "bundle-check.sh"):
            t = open(os.path.join(SRC, "cluster", "node", f)).read()
            self.assertNotIn("sha256sum --quiet -c MANIFEST.sha256", t, f)
            self.assertIn("bundle_verify", t, f)
        self.assertIn("! -path ./decisions.json", open(os.path.join(SRC, "cluster", "node", "export-manager.sh")).read())


# ================================================================================================ A7: the way back's node steps
class GobackFoldBeforeAny4xManagerA7(_Node):
    """E5-cluster-deb 07: back.folds failed on the master with an empty transcript: the whole-cluster way back runs it
    before any 4.x manager exists, and the sed of the missing ossec.conf killed the step (errexit, pipefail)."""

    def fold(self, tree):
        n = self.node(tree)
        self.assertFalse(os.path.exists(n.p("/var/ossec/etc/ossec.conf")))
        b = io.BytesIO()                                                     # the 4.x install files (pw4, ca4)
        with tarfile.open(fileobj=b, mode="w") as t:
            for name, data in (("wazuh-install-files/wazuh-passwords.txt", b"  indexer_username: 'admin'\n  indexer_password: 'not-a-real-one'\n"),
                               ("wazuh-install-files/root-ca.pem", b"fake ca\n")):
                i = tarfile.TarInfo(name)
                i.size = len(data)
                t.addfile(i, io.BytesIO(data))
        write(n.env["V4_TAR"], b.getvalue())
        return n.run("goback-fold-4x.sh", "https://10.0.0.1:9200")

    def test_the_step_goes_on_without_a_4x_manager(self):
        rc, out = self.fold(SRC)
        self.assertEqual(rc, 0, out)
        self.assertIn("no alerts.json fold on this node", out)



ASSISTANT4 = r"""#!/usr/bin/env bash
# a stand-in for the 4.x assistant: refuses an installed component unless -o, as the real one does
echo "assistant4 $*" >> "$FAKE/assistant.calls"
case "$1" in --wazuh-server) pk="wazuh-manager filebeat";; --wazuh-indexer) pk=wazuh-indexer;; --wazuh-dashboard) pk=wazuh-dashboard;; *) exit 0;; esac
over=0; for a in "$@"; do [ "$a" = -o ] && over=1; done
for p in $pk; do if [ -e "$FAKE/installed-$p" ] && [ "$over" = 0 ]; then echo "ERROR: Wazuh components ($p) are already installed. Use option -o|--overwrite"; exit 1; fi; done
for p in $pk; do case "$p" in filebeat) echo 7.10.2-1 > "$FAKE/installed-$p";; *) echo 4.14.10-1 > "$FAKE/installed-$p";; esac; done
echo "INFO: Installation finished"
"""


class GobackInstall4ResumesAfterACutA7(_Node):
    """E5-cluster-rpm 06 (CL-L9): a reboot during the 4.x assistant's Filebeat step left the packages installed; every
    rerun of the way back then failed at the reinstall ("already installed ... use -o"). Folded with install5.sh's
    success-only marker."""

    def setup(self, tree, installed=()):
        n = self.node(tree)
        fake = os.path.join(n.t, "fake")
        os.makedirs(fake)
        n.env["FAKE"] = fake
        n.stub("rpm", 'if [ "$1" = -q ] && [ -e "%s/installed-${@: -1}" ]; then cat "%s/installed-${@: -1}"; else echo "package ${@: -1} is not installed"; exit 1; fi' % (fake, fake))
        n.stub("shred", 'for a in "$@"; do [ "$a" = -u ] || rm -f "$a"; done')
        write(os.path.join(n.env["MIG_HOME"], "v4", "wazuh-install.sh"), ASSISTANT4, 0o755)
        write(n.env["V4_TAR"], "4.x install files (fake)\n")
        for p, v in installed:
            write(os.path.join(fake, "installed-" + p), v + "\n")
        return n

    def calls(self, n):
        p = os.path.join(n.env["FAKE"], "assistant.calls")
        return open(p).read().splitlines() if os.path.exists(p) else []

    CUT_SERVER = (("wazuh-manager", "4.14.10-1"), ("filebeat", "7.10.2-1"))

    def test_a_server_reinstall_cut_after_its_packages_goes_on_to_the_restore(self):
        n = self.setup(SRC, self.CUT_SERVER)
        rc, out = n.run("goback-install4.sh", "--wazuh-server", "wazuh-1")
        self.assertEqual(rc, 0, out)
        self.assertIn("did not record a success (a cut during the reinstall)", out)
        self.assertEqual(self.calls(n), [])


    def test_a_success_is_recorded_and_a_rerun_does_not_reinstall(self):
        n = self.setup(SRC)
        self.assertEqual(n.run("goback-install4.sh", "--wazuh-indexer", "node-1")[0], 0)
        self.assertTrue(os.path.exists(os.path.join(n.bundle, "state", "goback-install4--wazuh-indexer.ok")))
        rc, out = n.run("goback-install4.sh", "--wazuh-indexer", "node-1")
        self.assertEqual(rc, 0, out)
        self.assertIn("already reinstalled here by this step", out)
        self.assertEqual(len(self.calls(n)), 1)

    def test_a_part_installed_indexer_without_a_success_is_overwritten(self):
        n = self.setup(SRC, (("wazuh-indexer", "4.14.10-1"),))
        rc, out = n.run("goback-install4.sh", "--wazuh-indexer", "node-1")
        self.assertEqual(rc, 0, out)
        self.assertIn("reinstalled with -o", out)
        self.assertEqual(self.calls(n), ["assistant4 --wazuh-indexer node-1 -o"])

    def test_a_5x_package_still_there_stops(self):
        n = self.setup(SRC, (("wazuh-manager", "5.0.0-1"),))
        rc, out = n.run("goback-install4.sh", "--wazuh-server", "wazuh-1")
        self.assertNotEqual(rc, 0)
        self.assertIn("the 5.0 removal did not finish", out)
        self.assertEqual(self.calls(n), [])


# ================================================================================================ A8: the frozen fingerprint
H = helpers.load(os.path.join(SRC, "mig_helper.py"), "e5_helper")


def nested_idx(refuse_count=False):
    """_cat/indices counts nested sub-documents (2,261 for 2,241 alerts, RD3's ms-graph evidence), _count the alerts."""
    def idx(method, path, pw, body=None, **k):
        if path.startswith("/_cat/indices/"):
            return 200, [{"index": "wazuh-alerts-4.x-2026.11.25", "docs.count": "2261"}, {"index": "wazuh-alerts-4.x-2026.11.24", "docs.count": "10"},
                         {"index": "wazuh-states-vulnerabilities-x", "docs.count": "7"}]
        if path.endswith("/_count"):
            if refuse_count:
                return 403, {"error": "no"}
            return 200, {"count": {"/wazuh-alerts-4.x-2026.11.25/_count": 2241, "/wazuh-alerts-4.x-2026.11.24/_count": 10}[path]}
        raise AssertionError(path)
    return idx


class FingerprintCountsAlertsNotNestedDocsA8(unittest.TestCase):
    """E5-aio 01: phase 4 refused bundle A, "551790 alerts at the freeze; the dump manifest has ... 551770": the RD3 fold
    moved dump.py to _count, but the frozen fingerprint (indices()) still read _cat/indices docs.count. No test before."""

    def test_the_alert_indices_are_counted_with_count(self):
        with mock.patch.object(H, "idx", nested_idx()):
            r = H.indices("pw", "wazuh-*")
        self.assertEqual(r["wazuh-alerts-4.x-2026.11.25"], 2241)               # what dump.py's manifest holds
        self.assertEqual(r["wazuh-alerts-4.x-2026.11.24"], 10)
        self.assertEqual(r["wazuh-states-vulnerabilities-x"], 7)              # other indices keep docs.count

    def test_a_refused_count_is_an_error_not_a_number(self):
        with mock.patch.object(H, "idx", nested_idx(refuse_count=True)):
            self.assertIn("_error", H.indices("pw", "wazuh-*"))



# ================================================================================================ B9 and B16: the way back
class WholeClusterBackChecksEveryNodeFirstB9(_C):
    """E5-cluster-deb gap 2 (CL-L2): back.remove5 ran on every node in parallel and each checked its own bundle only then;
    the master refused (decisions.json in its manifest) after the worker, the three indexers and the dashboard had
    removed 5.0, and the cluster was left half removed."""
    M = "10.0.0.11"

    def back_with_the_master_refusing(self, tree, pat):
        c = self.cluster(tree)
        rc, out, _ = c.run("run", "--through", "master")
        self.assertEqual(rc, 0, out[-2000:])
        return c.run("back", FAIL_PAT=pat, FAIL_HOSTS=self.M)

    def test_one_refusal_and_nothing_is_removed_anywhere(self):
        rc, out, calls = self.back_with_the_master_refusing(SRC, "goback-remove5.sh check")
        self.assertNotEqual(rc, 0)
        self.assertIn("GOING BACK REFUSED before anything was changed on any node", out)
        steps = Cluster.steps(calls)
        checked = {n for n, st in steps if st.startswith("goback-remove5.sh check")}
        self.assertEqual(checked, {"10.0.0.1", "10.0.0.2", "10.0.0.11", "10.0.0.12", "10.0.0.21"})
        self.assertEqual([st for _, st in steps if not st.startswith("goback-remove5.sh check")], [])   # no guard, no removal


    def test_the_check_comes_first_and_the_way_back_then_goes_on(self):
        c = self.cluster()
        c.run("run", "--through", "master")
        rc, out, calls = c.run("back")
        self.assertEqual(rc, 0, out[-2000:])
        st = Cluster.steps(calls)
        first_change = min(i for i, (_, x) in enumerate(st) if not x.startswith("goback-remove5.sh check"))
        self.assertTrue(all(x.startswith("goback-remove5.sh check") for _, x in st[:first_change]))
        self.assertEqual(len(st[:first_change]), 5)
        self.assertEqual(st[first_change], (self.M, "guard.sh on agent"))

    def test_back_master_checks_the_master_first(self):
        c = self.cluster()
        c.run("run", "--through", "master")
        rc, out, calls = c.run("back", "master", FAIL_PAT="goback-remove5.sh check", FAIL_HOSTS=self.M)
        self.assertNotEqual(rc, 0)
        self.assertEqual(Cluster.steps(calls), [(self.M, "goback-remove5.sh check master")])


class TheNodeCheckBeforeGoingBackB9(_Node):
    """The node half of B9: goback-remove5.sh check, read-only."""

    def ready(self, n, role="master"):
        write(os.path.join(n.env["MIG_HOME"], "v5", "wazuh-install.sh"), "#!/bin/bash\nexit 0\n", 0o755)
        write(os.path.join(n.env["MIG_HOME"], "v4", "wazuh-install.sh"), "#!/bin/bash\nexit 0\n", 0o755)
        write(n.env["V4_TAR"], "4.x install files (fake)\n")
        write(os.path.join(n.bundle, "history", "manifest.json"), "{}\n")
        write(os.path.join(n.bundle, "v4", "etc", "client.keys"), "001 a any k\n")
        write(os.path.join(n.bundle, "state", "export.done"), "2026-11-25T12:59:00Z\n")
        subprocess.run("cd %s && find . -type f ! -path './state/*' ! -path './logs/*' ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256" % n.bundle,
                       shell=True, check=True)
        n.stub("rpm", 'echo "package ${@: -1} is not installed"; exit 1')
        return n

    def test_a_node_ready_to_go_back_passes_and_nothing_is_run(self):
        n = self.ready(self.node())
        rc, out = n.run("goback-remove5.sh", "check", "master")
        self.assertEqual(rc, 0, out)
        self.assertIn("this node can go back (master): bundle verified", out)
        self.assertNotIn("goback-remove-5.0.log", " ".join(os.listdir(os.path.join(n.bundle, "logs"))))

    def test_each_refusal_is_named(self):
        n = self.ready(self.node())
        write(os.path.join(n.bundle, "v4", "etc", "client.keys"), "changed\n")
        os.unlink(n.env["V4_TAR"])
        shutil.rmtree(os.path.join(n.bundle, "history"))
        rc, out = n.run("goback-remove5.sh", "check", "master")
        self.assertNotEqual(rc, 0)
        for m in ("the bundle does not match its manifest", "the original 4.x install files are not at", "no history dump in this bundle",
                  "going back is refused on this node"):
            self.assertIn(m, out)

    def test_a_node_still_on_4x_with_no_export_is_refused(self):
        n = self.ready(self.node())
        os.unlink(os.path.join(n.bundle, "state", "export.done"))
        os.unlink(os.path.join(n.bundle, "MANIFEST.sha256"))
        n.stub("rpm", 'if [ "${@: -1}" = wazuh-manager ]; then echo 4.14.10-1; else echo "package ${@: -1} is not installed"; exit 1; fi')
        rc, out = n.run("goback-remove5.sh", "check", "worker")
        self.assertNotEqual(rc, 0)
        self.assertIn("wazuh-manager 4.14.10-1 (4.x) is still installed on this node and this bundle holds no export of it", out)



class BackPushesTheToolB16(_C):
    """E5-cluster-deb gap 3, E5-cluster-rpm gap 7: only assess pushed the tool; after a fix the way back ran the old copy
    on the nodes until 'run --only assess' was typed."""

    def back_calls(self, tree):
        c = self.cluster(tree)
        c.run("run", "--through", "master")
        rc, out, calls = c.run("back")
        self.assertEqual(rc, 0, out[-2000:])
        return calls

    def test_back_copies_the_tool_to_every_node_before_any_step(self):
        calls = self.back_calls(SRC)
        first_step = min(i for i, x in enumerate(calls) if "run-step.sh" in x)
        pushed = {x.split()[0] for x in calls[:first_step] if "tar\\ -xzf" in x}
        self.assertEqual(pushed, {"10.0.0.1", "10.0.0.2", "10.0.0.11", "10.0.0.12", "10.0.0.21"})

    def test_a_node_whose_copy_differs_stops_the_way_back_before_anything(self):
        c = self.cluster()
        c.run("run", "--through", "master")
        rc, out, calls = c.run("back", FP="not-the-same")
        self.assertNotEqual(rc, 0)
        self.assertIn("the tool could not be copied to every node", out)
        self.assertEqual(Cluster.steps(calls), [])



# ================================================================================================ B10 to B12: raw at the finish
VERIFICATION_MD = """# Verification

| Result | Rules |
|---|---:|
| `REPRODUCED` | 4 |
| `NOT_REPRODUCED` | 1 |
| `SILENCED` | 0 |
| `NOT_SILENCED` | 0 |
| `NO_SAMPLE` | 1 |

| 4.x rule | Result | Oracle | Samples | Matched | Detector | Detail |
|---|---|---|---:|---:|---|---|
| 100201 | `REPRODUCED` | logtest (test) | 20 | 20 |  |  |
| 100202 | `NO_SAMPLE` | logtest (test) | 0 | 0 |  | a level 0 rule has no alerts: give its lines in samples/100202.log |
| 100300 | `NOT_REPRODUCED` | logtest (normalization: standard, detection: test) | 8 | 0 |  | the server reported no match |
"""


def rmig_state(space="custom", activated=True, detectors=True):
    return json.dumps({"version": 1, "last_activate": "2026-11-25T14:12:00+00:00" if activated else None, "set_aside": {},
                       "detectors": {"wazuh4-acmeshop-1": {"id": "d1", "rules": ["s1", "s2"]}} if detectors else {},
                       "resources": {"r1": {"type": "rule", "integration": "wazuh4-acmeshop", "space": space, "title": "100201"},
                                     "r2": {"type": "rule", "integration": "wazuh4-acmeshop", "space": space, "title": "100300"},
                                     "d1": {"type": "decoder", "integration": "wazuh4-acmeshop", "space": space, "title": "acmeshop"}}})


class _Raw(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)
        self.state = os.path.join(self.t, "state")
        self.rwork = os.path.join(self.t, "rwork")
        self.src = os.path.join(self.t, "ruleset-src")
        write(os.path.join(self.state, "unclassified.applied"), "verified-none\nraw\n")
        write(os.path.join(self.state, "ruleset.verify_summary"), "verify: REPRODUCED 4, NOT_REPRODUCED 1, SILENCED 0, NOT_SILENCED 0, NO_SAMPLE 1\n")
        write(os.path.join(self.rwork, "verification.md"), VERIFICATION_MD)
        write(os.path.join(self.src, "etc", "decoders", "acmeshop.xml"), '<decoder name="acmeshop">\n</decoder>\n<decoder name="acmeshop-login">\n</decoder>\n')
        self.dec = os.path.join(self.t, "decisions.json")

    def decide(self, mod=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = (mod or H).raw_decision(self.dec, self.state, self.rwork, self.src)
        return rc, buf.getvalue()

    def answer(self, a):
        d = json.load(open(self.dec))
        d["unclassified-finish"][0]["action"] = a
        json.dump(d, open(self.dec, "w"))


class RawRefusalNamesRulesNotTableRowsB11(_Raw):
    """E5-aio gap 5, E5-cluster-deb gap 9: the "rule not active" lines included verification.md's summary count rows."""

    def test_only_the_per_rule_rows_are_named(self):
        rc, out = self.decide()
        self.assertEqual(rc, 3)
        named = re.findall(r"rule not active: (.*)", out)
        self.assertEqual([x.split(" |")[0] for x in named], ["100202", "100300"])
        self.assertEqual([x.split(" |")[0] for x in json.load(open(self.dec))["unclassified-finish"][0]["rules_not_active"]], ["100202", "100300"])



class RawFactsSurviveTheFirstSweepB10(_Raw):
    """E5-aio gap 7, E5-cluster-rpm gap 4: after the first finish's secret sweep deleted ruleset-src, a later refusal said
    "(no custom decoder found)" for the acmeshop decoders."""

    def test_the_decoders_are_named_after_the_sweep(self):
        self.decide()
        shutil.rmtree(self.src)                                            # the first finish's sweep
        rc, out = self.decide()
        self.assertEqual(rc, 3)
        self.assertIn("would be dropped with raw off: acmeshop, acmeshop-login (as recorded before the bundle's ruleset copy was deleted)", out)
        self.assertEqual(json.load(open(os.path.join(self.state, "raw-at-finish-facts.json")))["custom_decoders"], ["acmeshop", "acmeshop-login"])


    def finish_with_4x_agents_left(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        rw = os.path.join(sh.bundle, "work", "ruleset-migration")
        write(os.path.join(rw, "verification.md"), VERIFICATION_MD)
        write(os.path.join(sh.bundle, "ruleset-src", "etc", "decoders", "acmeshop.xml"), '<decoder name="acmeshop">\n</decoder>\n')
        rc, out = sh.run('mkdir -p "$STATE"; printf "verified-none\\nraw\\n" > "$STATE/unclassified.applied"; echo "keep legacy: 005" > "$STATE/legacy.open"; '
                         'MIGRATION_DECISIONS=$BUNDLE_DIR/decisions.json; fi_raw_off; echo "rc=$?"')
        return sh, out

    def test_a_first_finish_that_keeps_raw_for_4x_agents_records_them_first(self):
        sh, out = self.finish_with_4x_agents_left(SRC)
        self.assertIn("RAW INDEXING KEPT ON: 4.x agents remain", out)
        f = json.load(open(os.path.join(sh.bundle, "state", "raw-at-finish-facts.json")))
        self.assertEqual(f["custom_decoders"], ["acmeshop"])
        self.assertEqual([x.split(" |")[0] for x in f["rules_not_active"]], ["100202", "100300"])



class ActivatedIsCheckedAgainstRmigB12(_Raw):
    """E5-aio gap 6: the answer "activated" was taken on the person's word; a wrong one switched raw off with the rules
    in the test space and dropped every custom-log event (E4-rpm gap 2 again)."""

    def answered_activated(self, mod=None, state=None):
        self.decide(mod)
        if state is not None:
            write(os.path.join(self.rwork, "work", "state.json"), state)
        self.answer("activated")
        return self.decide(mod)

    def test_without_an_activation_on_record_raw_stays_on(self):
        rc, out = self.answered_activated(state=rmig_state(space="test", activated=False))
        self.assertEqual(rc, 3)
        self.assertIn('you answered "activated", but rmig\'s record shows no activation', out)
        e = json.load(open(self.dec))["unclassified-finish"][0]
        self.assertIsNone(e["action"])
        self.assertEqual(e["refused"]["answer"], {"action": "activated"})
        self.assertFalse(os.path.exists(os.path.join(self.state, "raw.decision")))

    def test_rules_left_in_the_test_space_are_named(self):
        rc, out = self.answered_activated(state=rmig_state(space="test"))
        self.assertEqual(rc, 3)
        self.assertIn("2 of 2 migrated rule(s) are not in the custom space: 100201, 100300", out)

    def test_no_record_at_all_is_refused(self):
        rc, out = self.answered_activated()
        self.assertEqual(rc, 3)
        self.assertIn("cannot be read", out)

    def test_an_activation_on_record_lets_raw_go_off(self):
        rc, out = self.answered_activated(state=rmig_state())
        self.assertEqual(rc, 0, out)
        self.assertIn("agrees with rmig's record (activated 2026-11-25T14:12:00+00:00: 2 rule(s) in the custom space, detector(s) wazuh4-acmeshop-1)", out)
        self.assertIn("activated", open(os.path.join(self.state, "raw.decision")).read())



# ================================================================================================ B13: a second finish
class ASecondFinishDoesNotCloseLegacyAgainB13(_C):
    """E5-cluster-rpm gap 5, E5-cluster-deb gap 10: every finish ran legacy-close again (another manager restart each)
    although the legacy ports were already closed; a finish runs again after the raw-at-finish answer."""

    def finished_twice(self, tree):
        c = self.cluster(tree)
        for cmd in ("run", "confirm-no-return", "agents"):
            rc, out, _ = c.run(cmd)
            self.assertEqual(rc, 0, out[-2000:])
        rc, out, calls = c.run("finish", FAIL_PAT="finish-node.sh raw-off", FAIL_RC="3")   # the raw-at-finish question
        self.assertEqual(rc, 3, out[-2000:])
        self.assertTrue([s for s in Cluster.steps(calls) if s[1] == "finish-node.sh legacy-close decided"])
        return c.run("finish")

    def test_the_second_finish_skips_the_legacy_close(self):
        rc, out, calls = self.finished_twice(SRC)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("the legacy ports were closed on every manager at", out)
        self.assertFalse([s for s in Cluster.steps(calls) if s[1].startswith("finish-node.sh legacy")])
        self.assertIn("PHASE 11 finish END", out)



class ASecondFinishAllInOneB13(unittest.TestCase):
    def fi_legacy(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        return sh.run('mkdir -p "$STATE"; echo 2026-11-25T14:33:00Z > "$STATE/legacy.closed"; fu() { echo "FU-CALLED $*"; echo "legacy channel can be closed: NO"; }; '
                      'feed_wait() { echo FEED-WAIT; }; fi_legacy; echo "rc=$?"')

    def test_closed_once_is_closed(self):
        rc, out = self.fi_legacy(SRC)
        self.assertIn("not closed again", out)
        self.assertNotIn("FU-CALLED", out)
        self.assertIn("rc=0", out)



class LegacyCloseOnANodeOnceB13(_Node):
    def close_twice(self, tree):
        n = self.node(tree)
        c = n.p("/etc/wazuh-manager/wazuh-manager.conf")
        write(c, "<wazuh_config>\n  <remote>\n    <legacy>\n      <enabled>yes</enabled>\n    </legacy>\n  </remote>\n</wazuh_config>\n")
        write(n.p("/var/wazuh-manager/bin/wazuh-manager-conf"), "#!/bin/bash\nexit 0\n", 0o755)
        n.stub("ss", 'echo "LISTEN 0 4096 0.0.0.0:1517 0.0.0.0:*"; echo "LISTEN 0 4096 0.0.0.0:1516 0.0.0.0:*"')
        out = []
        for _ in range(2):
            rc, o = n.run("finish-node.sh", "legacy-close", "decided", env={"FEED_WAIT_MAX": "0"})
            self.assertEqual(rc, 0, o)
            out.append(o)
        return n, out

    def test_the_second_call_does_not_restart_the_manager(self):
        n, out = self.close_twice(SRC)
        self.assertIn("not closed again", out[1])
        self.assertEqual(n.called().count("systemctl restart wazuh-manager"), 1)



# ================================================================================================ B14: the cluster history in processes
class ClusterHistoryInProcessesB14(_Node):
    """E5-cluster-rpm gap 3: history5-master.sh did not pass HISTORY_PROCS (--procs): the cluster's history apply ran in
    threads while the all-in-one's ran in processes (1.9 times faster on the same month in E5-aio CL-L15)."""

    def argv(self, tree, env=None, cmd="apply"):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        n = self.node(tree, fake_src(tree, t, **{"history_load.py": ARGV_PRINTER}))
        n.stub("nproc", "echo 8")
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w") as tf:
            data = b'WAZUH_INDEXER_ADMIN_PASSWORD="not-a-real-one"\n'
            i = tarfile.TarInfo("wazuh-install-files/credentials.env")
            i.size = len(data)
            tf.addfile(i, io.BytesIO(data))
        write(n.env["V5_TAR"], b.getvalue())
        write(n.p("/etc/wazuh-manager/certs/indexer-ca.pem"), "fake ca\n")
        write(n.p("/etc/wazuh-manager/wazuh-manager.conf"), "<cluster>\n  <name>wazuh</name>\n</cluster>\n")
        write(os.path.join(n.bundle, "identity", "manifest.json"), json.dumps({"agents": [{"id": 2, "name": "a", "groups": ["default"]}]}))
        rc, out = n.run("history5-master.sh", "https://10.0.0.1:9200", cmd, env=env)
        m = re.search(r"ARGV (.*)$", out, re.M)
        self.assertIsNotNone(m, out)
        return json.loads(m.group(1))

    def test_apply_runs_in_processes_by_default(self):
        a = self.argv(SRC)
        self.assertEqual(a[a.index("--procs") + 1], "4")                   # half of 8 CPUs, as the all-in-one

    def test_the_inventory_setting_is_honoured(self):
        a = self.argv(SRC, {"HISTORY_PROCS": "0"})
        self.assertEqual(a[a.index("--procs") + 1], "0")

    def test_only_apply_takes_it(self):
        self.assertNotIn("--procs", self.argv(SRC, cmd="prove"))



class TheMasterTakesItsOwnProcsDefaultB14(_C):
    def node_env(self, tree, **env):
        c = self.cluster(tree)
        rc, out, calls = c.run("run", "--only", "assess", **env)
        self.assertEqual(rc, 0, out[-2000:])
        return [x for x in calls if "run-step.sh" in x]

    def test_the_controllers_cpu_count_is_not_sent_to_the_nodes(self):
        self.assertFalse([x for x in self.node_env(SRC) if "HISTORY_PROCS=" in x])

    def test_a_value_the_user_gives_is_sent(self):
        self.assertTrue(all("HISTORY_PROCS=6" in x for x in self.node_env(SRC, HISTORY_PROCS="6")))



# ================================================================================================ B15: a cluster base for the pre-copy
class PrecopyPlansAgainstAClusterBaseB15(_Node):
    """E5-cluster-rpm gap 2, E5-cluster-deb gap 4: the cluster pre-copy planned every node against the shipped all-in-one
    base, so each node got "$topology/mismatch" and "cluster/node_name" (a worker also "node_type"), questions the
    installed base never asks, and their answers then looped at the import (A4)."""

    def plan(self, tree, name, role):
        n = self.node(tree)
        cfg = os.path.join(n.bundle, "v4", "config")
        cluster_v4(cfg, node_name=name, node_type=role)
        shutil.copytree(STOCK, os.path.join(cfg, "stock"))
        shutil.copytree(os.path.join(FX, "groups"), os.path.join(n.bundle, "groups4"))
        rc, out = n.run("settings-node.sh", "plan-precopy", name, role, "10.0.0.11")
        d = json.load(open(os.path.join(n.bundle, "decisions.json")))
        return rc, out, sorted(i for i, e in d["settings"].items() if e.get("action") is None)

    def test_a_master_is_asked_only_its_own_questions(self):
        rc, out, asked = self.plan(SRC, "wazuh-1", "master")
        self.assertEqual(rc, 3, out[-2000:])
        self.assertIn("the pre-copy plan uses a cluster base: wazuh-1 (master), master 10.0.0.11", out)
        self.assertNotIn(TOPOLOGY, asked)
        self.assertFalse([i for i in asked if "/cluster[" in i], asked)
        self.assertEqual(len(asked), 5)                                         # the fixture's own five questions

    def test_a_worker_too(self):
        rc, out, asked = self.plan(SRC, "wazuh-2", "worker")
        self.assertEqual(rc, 3, out[-2000:])
        self.assertFalse([i for i in asked if "/cluster[" in i or "$topology" in i], asked)


    def test_the_controller_passes_the_node_its_name_role_and_master(self):
        c = Cluster(SRC)
        self.addCleanup(c.close)
        rc, out, calls = c.run("run", "--through", "precopy")
        self.assertEqual(rc, 0, out[-2000:])
        st = Cluster.steps(calls)
        self.assertIn(("10.0.0.12", "settings-node.sh plan-precopy wazuh-2 worker 10.0.0.11"), st)
        self.assertIn(("10.0.0.11", "settings-node.sh plan-precopy wazuh-1 master 10.0.0.11"), st)


# ================================================================================================ B17: the gate and --agents
class GateNamesAgentsLeftOutB17(unittest.TestCase):
    """E5-cluster-rpm gap 6: with FLEET_ARGS="--agents 002,003,004" the gate said "3 upgraded ..., 0 left on 4.x on
    purpose" while 005 stayed on 4.x."""

    def gate(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        write(os.path.join(sh.bundle, "fleet", "upgrade-state.json"), json.dumps({"agents": {"002": {"name": "acme-m-01", "state": "upgraded"}}}))
        write(os.path.join(sh.bundle, "fleet", "trust-audit.txt"), "002 acme-m-01 v5.0.0 ok verification_mode=full\n")
        write(os.path.join(sh.bundle, "preflight", "fleet-facts.json"), json.dumps({"agents": {"002": {"name": "acme-m-01"}, "005": {"name": "acme-w-02"}}}))
        return sh.run("ag_gate; echo rc=$?")

    def test_an_agent_outside_the_selection_is_named(self):
        rc, out = self.gate(SRC)
        self.assertIn("agent 005 acme-w-02", out)
        self.assertIn("not in this run's selection", out)
        self.assertIn("left out by the agents selection, still on 4.x: 005", out)
        self.assertIn("1 upgraded with trust proven, 1 left on 4.x on purpose", out)
        self.assertIn("rc=0", out)



# ================================================================================================ B18: enrollment without a password
class EnrollmentWithoutAPasswordIsSaidB18(unittest.TestCase):
    """E5-aio gap 4: a 4.x source without an enrollment password ends on 5.0 with use_password no (the settings stage
    carries it; a password-less enrollment was accepted after the finish), while assess said "5.0 enables use_password
    and generates one" and phase 8 "5.0 uses the one it generated". The behaviour is kept (the same as the source); the
    words now say it, and how to turn a password on."""

    def note(self, carry):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        return sh.run("enrollment_off_note %s" % carry)[1]

    def test_assess_says_the_password_stays_off_and_how_to_turn_it_on(self):
        out = self.note(1)
        self.assertIn("5.0 keeps it off (the settings stage carries use_password no)", out)
        self.assertIn("set <use_password>yes</use_password> in the <auth> section of /etc/wazuh-manager/wazuh-manager.conf", out)
        self.assertIn("restart wazuh-manager, and give it to every agent that enrolls", out)

    def test_without_the_settings_stage_5x_keeps_its_own_password(self):
        self.assertIn("5.0 keeps its installed use_password yes", self.note(0))

    def test_phase_8_reads_5xs_own_setting(self):
        self.assertIn("5.0 too (use_password no, carried by the settings stage). To require one: use_password yes",
                      H.enrollment_off_row({"use_password": "no", "authd_pass_sha256": "x"}))
        self.assertIn("5.0 requires the one in /etc/wazuh-manager/authd.pass (present)", H.enrollment_off_row({"use_password": "yes", "authd_pass_sha256": "x"}))
        self.assertEqual(H.use_password(os.path.join(AIO_BASE, "wazuh-manager.conf")), "yes")
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        write(os.path.join(t, "c.conf"), "<wazuh_config><auth>\n <port>1515</port>\n <use_password>no</use_password>\n</auth></wazuh_config>\n")
        self.assertEqual(H.use_password(os.path.join(t, "c.conf")), "no")



# ================================================================================================ B19: the retention WARNING's measure
from test_f4_retention import ms, DELETE_90  # noqa: E402


class RetentionWarningMeasuresFromTheSourceB19(unittest.TestCase):
    """E5-aio gap 3: after the way back the WARNING said "up to 146 day(s) longer than 4.x would have" by comparing the
    reload with the end of each index's day; the source had created those indices that day at 12:23Z, 41 minutes before
    the reload."""
    REC = {"policies": [{"policy_id": "p90", "policy": DELETE_90}], "attached": {"wazuh-alerts-4.x-2026.07.01": "p90", "wazuh-alerts-4.x-2026.07.02": "p90"}}
    CREATED = {"wazuh-alerts-4.x-2026.07.01": ms(2026, 11, 25, 13, 4), "wazuh-alerts-4.x-2026.07.02": ms(2026, 11, 25, 13, 5)}
    SOURCE = {"wazuh-alerts-4.x-2026.07.01": ms(2026, 11, 25, 12, 23), "wazuh-alerts-4.x-2026.07.02": ms(2026, 11, 25, 12, 24)}
    NOW = ms(2026, 11, 25, 13, 10)

    def test_measured_from_the_source_creation_date(self):
        lines = H.restored_age_report_of(self.REC, self.CREATED, self.NOW, self.SOURCE)
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("WARNING 2 restored alert index(es) count their ISM age from a date after their own creation on 4.x", lines[0])
        self.assertIn("up to 41 minute(s) longer than 4.x would have (measured from each index's own creation date on 4.x)", lines[0])

    def test_where_the_dump_recorded_none_the_day_in_the_name_stays_the_measure(self):
        lines = H.restored_age_report_of(self.REC, self.CREATED, self.NOW, {"wazuh-alerts-4.x-2026.07.01": self.SOURCE["wazuh-alerts-4.x-2026.07.01"]})
        self.assertIn("up to 145 day(s) longer", lines[0])                       # 2026.07.02: from the end of its day
        self.assertIn("where the dump recorded it, else from the end of the day in its name", lines[0])

    def test_the_dump_records_are_read_beside_the_ism_record(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        write(os.path.join(t, "history", "indices", "wazuh-alerts-4.x-2026.07.01.json"), json.dumps({"creation_date": self.SOURCE["wazuh-alerts-4.x-2026.07.01"], "shards": 1}))
        write(os.path.join(t, "history", "indices", "wazuh-alerts-4.x-2026.07.02.json"), json.dumps({"shards": 1}))
        self.assertEqual(H.source_creation_dates(os.path.join(t, "history")), {"wazuh-alerts-4.x-2026.07.01": self.SOURCE["wazuh-alerts-4.x-2026.07.01"]})



# ================================================================================================ B20: the controller's mask
MASK_LINES = ["kept (checked: none of the carried secret values, no private key and no credential hash in them): history/manifest.json, journal.ndjson",
              "    Password: S3cr3t.x", "X=1 WAZUH_API_PASSWORD=abc Y=2 token: zz", '{"password": "a b", "user": "u"}',
              "  indexer_password: 'q w'", "use the Filebeat Keystore username and password."]


class TheMaskHidesTheValueOnlyB20(unittest.TestCase):
    """E5-cluster-deb gap 8: the controller's password mask blanked the secret sweep's whole "kept (...)" line (it held
    "password hash in them):")."""

    def mask(self, script):
        fn = re.search(r"^mask_passwords\(\) \{.*?; \}", open(script).read(), re.M | re.S).group(0)
        r = subprocess.run(["bash", "-c", fn + "\nmask_passwords"], input="\n".join(MASK_LINES) + "\n", capture_output=True, text=True)
        return r.stdout.splitlines()

    def test_values_are_masked_and_the_rest_is_kept(self):
        for script in (os.path.join(SRC, "migrate.sh"), os.path.join(SRC, "cluster", "node", "common.sh")):
            out = self.mask(script)
            self.assertEqual(out[0], MASK_LINES[0])                                  # the sweep's line, whole
            self.assertEqual(out[1], "    Password: MASKED")
            self.assertEqual(out[2], "X=1 WAZUH_API_PASSWORD=MASKED Y=2 token: MASKED")
            self.assertEqual(out[3], '{"password": MASKED, "user": "u"}')
            self.assertEqual(out[4], "  indexer_password: MASKED")
            self.assertEqual(out[5], MASK_LINES[5])
            for secret in ("S3cr3t", "abc", "zz", "a b", "q w"):
                self.assertNotIn(secret, "\n".join(out[1:5]))

    def test_the_sweep_line_has_no_credential_name_before_its_colon(self):
        t = open(os.path.join(SRC, "bundle_secrets.py")).read()
        self.assertIn("kept (checked: none of the carried secret values, no private key and no credential hash in them)", t)



# ================================================================================================ B21: small items
class SmallItemsB21(_Node):
    """E5-cluster-deb gap 7 and 12, E5-cluster-rpm gap 7: wazuh.gpg~ left; "allowed (port)port"; check5-manager.sh
    printing the key count twice; the repair's empty summary when the output test fails; no way out named after a failed
    master install; one fingerprint form."""

    def test_the_keyrings_backup_copy_is_removed(self):
        self.assertIn("/usr/share/keyrings/wazuh.gpg~", open(os.path.join(SRC, "cluster", "node", "remove4x.sh")).read())
        self.assertIn("/usr/share/keyrings/wazuh.gpg~", re.search(r"^REPO_FILES=.*$", open(os.path.join(SRC, "migrate.sh")).read(), re.M).group(0))

    def facts(self, tree):
        n = self.node(tree)
        n.stub("ufw", 'if [ "$1" = status ]; then echo "Status: active"; echo "1514/tcp                   ALLOW       Anywhere"; fi')
        rc, out = n.run("node-facts.sh", "master")
        return out

    def test_the_firewall_line_says_allowed_once(self):
        out = self.facts(SRC)
        self.assertIn("1514/tcp allowed (port)\n", out)
        self.assertIn("1515/tcp NOT allowed", out)
        self.assertNotIn("allowed (port)port", out)


    def check5(self, tree):
        n = self.node(tree)
        write(n.p("/etc/wazuh-manager/wazuh-manager.conf"), "<cluster><name>wazuh</name></cluster>\n")
        write(n.p("/etc/wazuh-manager/client.keys"), "")
        n.stub("ss", "true")
        n.stub("openssl", "true")
        return n.run("check5-manager.sh")[1]

    def test_an_empty_registry_is_counted_once(self):
        out = self.check5(SRC)
        self.assertIn("client.keys: 0 line(s)", out)
        self.assertNotIn("client.keys: 0\n", out)


    def repair_with_a_failing_output_test(self, tree):
        n = self.node(tree)
        r = os.path.join(n.bundle, "v4", "rollback")
        tgz(os.path.join(r, "etc-filebeat.tar.gz"), {"etc/filebeat/filebeat.yml": b"output.elasticsearch:\n  hosts: [x]\n"})
        tgz(os.path.join(r, "filebeat-module-wazuh.tar.gz"), {"usr/share/filebeat/module/wazuh/module.yml": b"M"})
        write(n.p("/var/lib/filebeat/filebeat.keystore"), b"KS")
        write(n.p("/etc/filebeat/filebeat.yml"), "output.elasticsearch:\n  hosts: [x]\n")
        write(n.p("/usr/share/filebeat/module/wazuh/module.yml"), "M")
        n.stub("rpm", "exit 0")
        n.stub("filebeat", 'echo "elasticsearch: https://10.0.0.1:9200..."; echo "  TLS... ERROR x509: certificate signed by unknown authority"; exit 1')
        n.stub("systemctl", '[ "$1" = is-active ] && { [ "$2" = -q ] && exit 0; echo active; }; exit 0')
        return n.run("filebeat-repair.sh")

    def test_a_failed_output_test_is_said(self):
        rc, out = self.repair_with_a_failing_output_test(SRC)
        self.assertIn("filebeat active; filebeat test output failed: TLS... ERROR x509: certificate signed by unknown authority", out)



class SmallItemsControllerB21(_C):
    def test_a_failed_master_install_names_the_way_out(self):
        c = self.cluster()
        c.run("run", "--through", "indexers")
        rc, out, calls = c.run("run", "--through", "master", FAIL_PAT="install5.sh -wm", FAIL_HOSTS="10.0.0.11")
        self.assertNotEqual(rc, 0)
        self.assertIn("To return the master alone to 4.x: '", out)
        self.assertIn("back master'", out)


    def test_the_printed_fingerprint_is_the_lc_all_c_src_form(self):
        c = self.cluster()
        rc, out, calls = c.run("run", "--only", "assess")
        self.assertEqual(rc, 0, out[-2000:])
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        shutil.copytree(SRC, os.path.join(t, "src"), ignore=shutil.ignore_patterns("__pycache__"))
        want = subprocess.run("cd %s && find src -type f ! -path '*/__pycache__/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16" % t,
                              shell=True, capture_output=True, text=True).stdout.strip()
        self.assertIn("the tool is in /root/wazuh-migration/src (%s)" % want, out)


class DebPackagesListedOnlyWhenInstalledB21(_Node):
    """E5-cluster-deb gap 7: deb `pkgs` listed packages dpkg knows but are not installed ("wazuh-agent ;wazuh-api ;")."""

    def pkgs(self, tree):
        n = self.node(tree)
        n.stub("dpkg-query", 'case "$*" in *Status*) printf "installed wazuh-indexer 5.0.0-1\\nnot-installed wazuh-agent \\nconfig-files wazuh-api 4.0.0\\n";; '
                             '*) printf "wazuh-indexer 5.0.0-1\\nwazuh-agent \\nwazuh-api 4.0.0\\n";; esac')
        return bash(". %s; pkgs" % os.path.join(n.node, "common.sh"), dict(n.env, PKGFAM="deb"))[1]

    def test_only_installed_packages(self):
        self.assertEqual(self.pkgs(SRC).split("\n")[0:2], ["wazuh-indexer 5.0.0-1", ""])



if __name__ == "__main__":
    unittest.main()
