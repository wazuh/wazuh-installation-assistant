"""CL1: the cluster flow as a product command.

Item 0, the fixes found elsewhere and applied first: E4-rpm fix 01 (identity stage resumes after a cut between the carried
rbac.db and the service password reset), E4-breaker fixes 02 and 03 (a 4.x source without an enrollment password), RD3
(dump.py counts each index with _count, not _cat/indices docs.count). Items 1 to 6: the cluster command
(migrate-cluster.sh), no lab values, deb and rpm, parity with the all-in-one on the master, the guide's four unchecked
points and E4-cluster's new gaps."""
import contextlib
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import helpers
from test_e2_cluster import NodeSteps, tgz, write
from test_f4_retention import FakeOpenSearch, Served

SRC = helpers.SRC
IS = helpers.load(os.path.join(SRC, "identity_stage.py"), "cl1_identity_stage", extra_path=SRC)


# =============================================================================================== item 0: pending fixes
class IdentityResumesAfterARbacCutE4Rpm01(unittest.TestCase):
    """E4-rpm fix 01: a reboot 0.25 s after the stage wrote the carried rbac.db back left 'wazuh' on its 4.x password;
    every rerun stopped on 'API login as wazuh failed: HTTP 401'."""

    class Api:
        def __init__(self, err):
            self.err = err

        def authenticate(self):
            if self.err:
                raise SystemExit(self.err)

    def test_a_401_to_the_published_password_is_recognised_and_other_failures_still_stop(self):
        self.assertTrue(IS.published_login_refused(self.Api('API login as wazuh failed: HTTP 401 b\'{"title": "Unauthorized"}\'')))
        self.assertFalse(IS.published_login_refused(self.Api(None)))
        with self.assertRaises(SystemExit):
            IS.published_login_refused(self.Api("API login as wazuh failed: connection refused"))

    def test_the_resume_resets_the_service_passwords_before_the_preflight(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        open(os.path.join(t, "rbac.db.pre-migration"), "w").close()
        calls = []

        class Stop(Exception):
            pass

        def preflight(*a, **k):
            calls.append("preflight")
            raise Stop()
        args = mock.Mock(with_rbac=True, with_password=False, workers=4, state=os.path.join(t, "state"), limit_mode="raise", bundle=t)
        with mock.patch.object(IS, "RBAC_DB", os.path.join(t, "rbac.db")), \
                mock.patch.object(IS, "Api", lambda *a, **k: self.Api("API login as wazuh failed: HTTP 401 x")), \
                mock.patch.object(IS, "read_api_yaml_limit", lambda: (300, None)), mock.patch.object(IS, "load_bundle", lambda b: ({}, {}, {})), \
                mock.patch.object(IS, "reset_service_passwords", lambda st: calls.append("reset") or True), \
                mock.patch.object(IS, "preflight", preflight), mock.patch.object(IS, "log", lambda *a: None):
            with self.assertRaises(Stop):
                IS.cmd_run(args)
        self.assertEqual(calls, ["reset", "preflight"])



class NoEnrollmentPasswordOnTheSourceE4Breaker02And03(unittest.TestCase):
    """E4-breaker fixes 02 and 03: the 4.x assistant's default all-in-one enrolls without a password; the identity stage
    blocked ('the bundle has no authd.pass') and phase 8 called the password LOST. Both flows."""

    def pwflag(self, tree, with_file):
        t = tempfile.mkdtemp(prefix="cl1-pw-")
        self.addCleanup(shutil.rmtree, t, True)
        os.makedirs(os.path.join(t, "identity"))
        if with_file:
            open(os.path.join(t, "identity", "authd.pass"), "w").write("x" * 20 + "\n")
        m = re.search(r"^pwflag\(\) \{.*\}$", open(os.path.join(tree, "migrate.sh")).read(), re.M)
        if not m:
            return None
        r = subprocess.run(["bash", "-c", m.group(0) + '; BUNDLE_DIR="$1"; pwflag', "x", t], capture_output=True, text=True)
        return r.returncode, r.stdout.strip()

    def test_the_all_in_one_passes_with_password_only_when_the_source_had_one(self):
        self.assertEqual(self.pwflag(SRC, True), (0, "--with-password"))
        self.assertEqual(self.pwflag(SRC, False), (0, ""))
        txt = open(os.path.join(SRC, "migrate.sh")).read()
        self.assertEqual(txt.count('--workers "$(idw)" $(pwflag) --with-rbac'), 2)
        self.assertNotIn('--workers "$(idw)" --with-password', txt)

    def cluster_stage_argv(self, tree, with_file):
        n = NodeSteps(tree)
        self.addCleanup(n.close)
        argv = os.path.join(n.t, "argv.json")
        write(n.p("/var/wazuh-manager/framework/python/bin/python3"),
              "#!%s\nimport json, sys\njson.dump(sys.argv[1:], open(%r, 'w'))\nprint('GATE PASS (fake stage)')\n" % (sys.executable, argv), 0o755)
        if with_file:
            write(os.path.join(n.bundle, "identity", "authd.pass"), "x" * 20 + "\n")
        rc, out = n.run("identity-stage-master.sh", env={"STOP_AFTER": "preflight"})
        self.assertEqual(rc, 0, out)
        return json.load(open(argv))

    def test_the_cluster_identity_step_follows_the_same_rule(self):
        self.assertIn("--with-password", self.cluster_stage_argv(SRC, True))
        self.assertNotIn("--with-password", self.cluster_stage_argv(SRC, False))


    def test_the_compare_does_not_call_an_absent_source_password_lost(self):
        txt = open(os.path.join(SRC, "mig_helper.py")).read()
        i = txt.index('if e4.get("authd_pass_sha256") is None:')
        self.assertIn('"NOT USED ON 4.x"', txt[i:i + 600])


class NestedDocs(FakeOpenSearch):
    """A 4.x index whose template maps fields as nested (ms-graph evidence): _cat/indices docs.count counts every nested
    sub-document too, _count counts the alerts."""

    def route(self, method, parts, raw):
        if parts and parts[0] == "_cat":
            return 200, [{"index": n, "pri": "1", "docs.count": str(3 * len(self.idx[n]["docs"])), "store.size": "1"} for n in self.match(parts[2])]
        return super().route(method, parts, raw)


class DumpCountsAlertsNotNestedDocsRD3(unittest.TestCase):
    """RD3: dump.py took each index's expected count from _cat/indices docs.count; with nested sub-documents the history
    proof could never pass (1034 alerts, 1054 expected) and `on` refused."""

    def dump(self, tree):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        s = Served(NestedDocs({"wazuh-alerts-4.x-2026.11.20": (None, 4)}))
        self.addCleanup(s.close)
        out = os.path.join(t, "b")
        r = subprocess.run([sys.executable, os.path.join(tree, "dump.py"), "--url", s.url, "--user", "admin", "--password-env", "P",
                            "--out", out, "--workers", "1"], env=dict(os.environ, P="pw", PYTHONDONTWRITEBYTECODE="1"),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout.decode())
        m = json.load(open(os.path.join(out, "manifest.json")))
        run = json.load(open(os.path.join(out, "runs", "run-001.json")))
        return m["indices"]["wazuh-alerts-4.x-2026.11.20"]["docs_expected"], run["count_start"]["wazuh-alerts-4.x-2026.11.20"]

    def test_the_expected_count_is_the_number_of_alerts(self):
        self.assertEqual(self.dump(SRC), (4, 4))



# =============================================================================================== item 1: one command
FAKE_SSH = r"""#!/usr/bin/env bash
# a stand-in for ssh: the node and the command into $CALLS; stdin consumed; FAIL_PAT/FAIL_RC make a matching command fail
while [ $# -gt 0 ]; do case "$1" in -i|-p|-o) shift 2;; *@*) host=${1#*@}; shift; break;; *) shift;; esac; done
cmd="$*"
[ -t 0 ] || cat > /dev/null
echo "$host $cmd" >> "$CALLS"
if [ -n "${FAIL_PAT:-}" ] && [[ "$cmd" == *$FAIL_PAT* ]]; then echo "FATAL: refused (fake)"; exit "${FAIL_RC:-1}"; fi
case "$cmd" in
  *"cat "*client.keys*) echo "001 agent-1 any 0123456789abcdef";;
  *"find . -type f"*) echo "$FP";;
  *"cat "*decisions.json*) [ -n "${DECISIONS:-}" ] && echo "$DECISIONS";;
  *"cat "*wazuh-install-files.tar*) echo "TAR-CONTENT";;
  *run-step.sh*) echo "step ok";;
esac
exit 0
"""


def src_fp(tree):
    # E5 fold (one fingerprint form): the tool's own form since the fold, "src/<path>" in C-locale order; a tree before the
    # fold (PRE) prints the "./<path>" form, so both are given: the fake node answers what the tree under test asks for
    sed = "" if os.path.exists(os.path.join(tree, "migrate-cluster.sh")) and "FP_CMD=" not in open(os.path.join(tree, "migrate-cluster.sh")).read() else " | sed 's#  \\./#  src/#'"
    out = subprocess.run(("cd %s && find . -type f ! -path '*/__pycache__/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum" + sed + " | sha256sum | cut -c1-16") % tree,
                         shell=True, capture_output=True, text=True).stdout.strip()
    return out


class Cluster:
    """A controller sandbox: inventory, key, inputs and a fake SSH; runs src/migrate-cluster.sh."""
    NODES = [{"name": "node-1", "role": "indexer", "address": "10.0.0.1"}, {"name": "node-2", "role": "indexer", "address": "10.0.0.2"},
             {"name": "wazuh-1", "role": "master", "address": "10.0.0.11"}, {"name": "wazuh-2", "role": "worker", "address": "10.0.0.12"},
             {"name": "dashboard", "role": "dashboard", "address": "10.0.0.21"}]

    def __init__(self, tree=SRC, **over):
        self.t = tempfile.mkdtemp(prefix="cl1-")
        self.tree = tree
        p = lambda *x: os.path.join(self.t, *x)
        for f in ("v4tar", "v4.sh", "v5.sh", "config.yml", "idtool.py"):
            write(p("in", f), "x\n")
        os.makedirs(p("in", "rmig"))
        write(p("key"), "k\n", 0o600)
        write(p("fakessh"), FAKE_SSH, 0o755)
        self.calls = p("calls")
        open(self.calls, "w").close()
        self.inv = {"ssh": {"user": "root", "key": p("key")}, "state_dir": p("st"),
                    "inputs": {"v4_install_files": p("in", "v4tar"), "v4_assistant": p("in", "v4.sh"), "v5_assistant": p("in", "v5.sh"),
                               "v5_config": p("in", "config.yml"), "identity_tool": p("in", "idtool.py"), "ruleset_tool": p("in", "rmig")},
                    "nodes": [dict(n) for n in self.NODES], "settings": {}}
        self.inv.update(over)
        self.save()
        self.env = dict(os.environ, CALLS=self.calls, FP=src_fp(tree), MIG_SSH=p("fakessh"), REGISTRY_WAIT="0", REGISTRY_TRIES="2")

    def save(self):
        write(os.path.join(self.t, "inv.json"), json.dumps(self.inv))

    def run(self, *args, **env):
        open(self.calls, "w").close()
        e = dict(self.env, **env)
        r = subprocess.run(["bash", os.path.join(self.tree, "migrate-cluster.sh"), "--inventory", os.path.join(self.t, "inv.json")] + list(args),
                           env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        return r.returncode, r.stdout.decode(errors="replace"), [" ".join(x.replace("\\,", ",").split()) for x in open(self.calls).read().splitlines()]

    @staticmethod
    def steps(calls):
        """(node address, node step and its arguments) of every run-step.sh call, in order."""
        out = []
        for c in calls:
            m = re.search(r"run-step\.sh \S+ (\S+)(.*)$", c)
            if m:
                out.append((c.split()[0], (m.group(1) + m.group(2)).strip()))
        return out

    def close(self):
        shutil.rmtree(self.t, ignore_errors=True)


class _C(unittest.TestCase):
    def cluster(self, tree=SRC, **over):
        c = Cluster(tree, **over)
        self.addCleanup(c.close)
        return c

    def index(self, steps, node, text):
        for i, (n, s) in enumerate(steps):
            if n == node and s.startswith(text):
                return i
        self.fail("no step %r on %s in %s" % (text, node, steps))


class OneCommandItem1(_C):
    """Brief item 1: one command reads the inventory and runs the phases of the all-in-one with the same state file,
    resume, --through, --only, decisions file and stop messages (before: k5.sh lab stages over lab helpers)."""

    def test_the_whole_run_goes_in_order_c_and_stops_at_the_point_of_no_return(self):
        c = self.cluster()
        rc, out, calls = c.run("run")
        self.assertEqual(rc, 0, out[-3000:])
        st = Cluster.steps(calls)
        M, W, I1 = "10.0.0.11", "10.0.0.12", "10.0.0.1"
        # pre-copy: the retention before the first dump (F4), then the dump
        self.assertLess(self.index(st, M, "retention-4x.sh read"), self.index(st, M, "history-dump.sh"))
        # the indexers go while both 4.x managers serve; the master before the worker; the worker after the master opened
        self.assertLess(self.index(st, I1, "remove4x.sh"), self.index(st, M, "freeze-manager.sh"))
        self.assertLess(self.index(st, M, "guard.sh on agent"), self.index(st, M, "remove4x.sh"))
        self.assertLess(self.index(st, M, "open-node.sh"), self.index(st, W, "freeze-manager.sh"))
        self.assertLess(self.index(st, W, "settings-node.sh apply-worker"), self.index(st, W, "open-node.sh"))
        # every fold into the history bundle before the history loads; the aliases after the proof
        self.assertLess(self.index(st, M, "fold-alertsjson.sh --merge"), self.index(st, M, "history5-master.sh https://10.0.0.1:9200 apply"))
        self.assertLess(self.index(st, M, "history5-master.sh https://10.0.0.1:9200 prove"), self.index(st, M, "history5-master.sh https://10.0.0.1:9200 on"))
        self.assertIn("PHASE 9: POINT OF NO RETURN", out)
        for f in ("journal.ndjson", "state/phase.history", "results/precopy.history.json"):
            self.assertTrue(os.path.exists(os.path.join(c.t, "st", f)), f)
        # the cluster's facts reach every node step: the inventory's manager names and one indexer
        self.assertTrue(all("CLUSTER_NODES=wazuh-1,wazuh-2" in x and "IDX5_HOST=10.0.0.1" in x for x in calls if "run-step.sh" in x))

    def test_resume_through_and_only(self):
        c = self.cluster()
        rc, out, calls = c.run("run", "--through", "precopy")
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("stopped after phase precopy as asked (--through)", out)
        self.assertFalse([s for s in Cluster.steps(calls) if "filebeat-stop" in s[1]])
        rc, out, calls = c.run("run", "--through", "freeze")
        self.assertIn("PHASE 2 precopy: already complete", out)
        self.assertTrue([s for s in Cluster.steps(calls) if "filebeat-stop" in s[1]])
        rc, out, calls = c.run("run", "--only", "precopy")
        self.assertEqual(rc, 0)
        self.assertIn("skip  history: dump the alerts", out)            # the steps' own markers within a phase
        rc, out, _ = c.run("run", "--only", "nonsense")
        self.assertNotEqual(rc, 0)
        self.assertIn("no phase 'nonsense'", out)

    def test_a_failed_node_step_stops_the_run_and_nothing_after_it_runs(self):
        c = self.cluster()
        rc, out, calls = c.run("run", FAIL_PAT="export-manager.sh master")
        self.assertNotEqual(rc, 0)
        self.assertIn("FAIL  the master's export", out)
        self.assertFalse([s for s in Cluster.steps(calls) if s[0] == "10.0.0.11" and "remove4x" in s[1]])
        r = json.load(open(os.path.join(c.t, "st", "results", "master.export.json")))
        self.assertEqual(r["result"], "failed")

    def test_an_open_settings_question_stops_with_the_nodes_decisions_file(self):
        c = self.cluster()
        q = '{"settings": [{"id": "x", "action": null}]}'
        rc, out, calls = c.run("run", FAIL_PAT="plan-precopy", FAIL_RC="3", DECISIONS=q)
        self.assertEqual(rc, 3, out[-2000:])
        self.assertIn('answer the open entries ("action": null) in %s/st/decisions/wazuh-1.json (node wazuh-1)' % c.t, out)
        self.assertEqual(json.load(open(os.path.join(c.t, "st", "decisions", "wazuh-1.json"))), json.loads(q))
        self.assertEqual(os.stat(os.path.join(c.t, "st", "decisions", "wazuh-1.json")).st_mode & 0o077, 0)
        # the answered file goes back to the node before the next attempt
        rc, out, calls = c.run("run", "--only", "precopy")
        self.assertTrue(any("decisions.json.part" in x for x in calls if x.startswith("10.0.0.11")))

    def test_the_inventory_is_checked_first(self):
        c = self.cluster()
        c.inv["nodes"] = [n for n in c.inv["nodes"] if n["role"] != "master"]
        os.chmod(c.inv["ssh"]["key"], 0o644)
        c.inv["work_dir"] = "/var/ossec/mig"
        c.save()
        rc, out, calls = c.run("run")
        self.assertNotEqual(rc, 0)
        for m in ("exactly one master is needed", "can be read by others than its owner", "work_dir /var/ossec/mig is under /var/ossec"):
            self.assertIn(m, out)
        self.assertEqual(calls, [])                                      # no node was touched

    def test_the_install_files_go_host_to_host_and_inputs_may_already_be_on_a_node(self):
        c = self.cluster()
        c.inv["inputs"]["v4_install_files"] = "node:node-1:/root/wazuh-install-files.tar"
        c.save()
        rc, out, calls = c.run("run", "--through", "indexers")
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("10.0.0.1 cat /root/wazuh-install-files.tar", calls)          # the 4.x files from node-1 itself
        self.assertIn("10.0.0.1 cat /root/wazuh-migration/v5/wazuh-install-files.tar", calls)   # the 5.0 files from the setup node
        here = [os.path.join(d, f) for d, _, fs in os.walk(c.t) for f in fs if f != "fakessh" and "TAR-CONTENT" in open(os.path.join(d, f), errors="replace").read()]
        self.assertEqual(here, [])

    def test_k5_is_the_lab_driver_calling_the_command(self):
        self.assertIn('bash "$(dirname "$(readlink -f "$0")")/migrate-cluster.sh"', open(os.path.join(SRC, "migrate.sh")).read())


class TheRunStepIsDetachedItem1(unittest.TestCase):
    """K5: node steps run detached from the controller; a rerun follows a step still running instead of starting it again."""

    def test_a_killed_follower_does_not_kill_the_step_and_a_rerun_follows_it(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        shutil.copy(os.path.join(SRC, "cluster", "node", "run-step.sh"), t)
        write(os.path.join(t, "demo.sh"), "#!/bin/bash\necho start $*; sleep 2; echo end; exit 4\n", 0o755)
        env = dict(os.environ, BUNDLE_DIR=os.path.join(t, "b"), RUN_STEP_POLL="0.2")
        p = subprocess.Popen(["bash", os.path.join(t, "run-step.sh"), "s1", "demo.sh", "a"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        import time
        time.sleep(0.7)
        p.kill()
        p.wait()
        r = subprocess.run(["bash", os.path.join(t, "run-step.sh"), "s1", "demo.sh", "a"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 4)
        self.assertIn("still running on this node", r.stdout)
        self.assertIn("end", r.stdout)
        log = open(os.path.join(t, "b", "logs", "steps", "s1.log")).read()
        self.assertEqual(log.count("start a"), 1)                         # started once


class TheCommandsAroundTheRunItem1And4(_C):
    """Phases 9 to 11 and going back on the cluster: the point of no return, the agents step (feed wait on every
    manager), the finish (group pass, raw off by decision, history data, every bundle's secrets), the way back."""

    def ran(self):
        c = self.cluster()
        rc, out, _ = c.run("run")
        self.assertEqual(rc, 0, out[-2000:])
        return c

    def test_the_point_of_no_return_and_the_back_refusal_after_it(self):
        c = self.cluster()
        rc, out, _ = c.run("confirm-no-return")
        self.assertNotEqual(rc, 0)
        self.assertIn("phases 1 to 8 are not complete", out)
        rc, out, _ = c.run("agents")
        self.assertIn("the point of no return is not confirmed", out)
        c = self.ran()
        rc, out, _ = c.run("confirm-no-return")
        self.assertEqual(rc, 0, out)
        self.assertIn("POINT OF NO RETURN confirmed", out)
        rc, out, calls = c.run("back")
        self.assertNotEqual(rc, 0)
        self.assertIn("going back is not offered", out)
        self.assertEqual(Cluster.steps(calls), [])

    def test_agents_wait_for_the_feed_on_every_manager_before_the_gate(self):
        c = self.ran()
        c.run("confirm-no-return")
        rc, out, calls = c.run("agents", FLEET_ARGS="--node-address wazuh-2=mgr2.example")
        self.assertEqual(rc, 0, out[-2000:])
        st = Cluster.steps(calls)
        g = self.index(st, "10.0.0.11", "agents-node.sh gate")
        for m in ("10.0.0.11", "10.0.0.12"):
            self.assertLess(self.index(st, m, "feed-node.sh"), g)
        self.assertIn(("10.0.0.11", "agents-node.sh run --node-address wazuh-2=mgr2.example"), st)

    def test_the_finish_runs_the_group_pass_raw_off_history_data_and_every_secret_sweep(self):
        c = self.ran()
        c.run("confirm-no-return")
        c.run("agents")
        rc, out, calls = c.run("finish")
        self.assertEqual(rc, 0, out[-2000:])
        st = Cluster.steps(calls)
        for node, s in (("10.0.0.11", "finish-node.sh legacy-decide"), ("10.0.0.11", "finish-node.sh legacy-close decided"),
                        ("10.0.0.12", "finish-node.sh legacy-close decided"), ("10.0.0.11", "finish-node.sh raw-off"),
                        ("10.0.0.11", "finish-node.sh groups-post"), ("10.0.0.11", "finish-node.sh history-data"),
                        ("10.0.0.11", "finish-node.sh secrets"), ("10.0.0.12", "finish-node.sh secrets"), ("10.0.0.1", "finish-node.sh secrets")):
            self.index(st, node, s)
        self.assertIn("PHASE 11 finish END", out)

    def test_raw_off_refused_stops_the_finish_with_the_masters_decisions_file(self):
        c = self.ran()
        c.run("confirm-no-return")
        c.run("agents")
        rc, out, calls = c.run("finish", FAIL_PAT="finish-node.sh raw-off", FAIL_RC="3")
        self.assertEqual(rc, 3)
        self.assertIn("decisions/wazuh-1.json (node wazuh-1)", out)
        self.assertFalse([s for s in Cluster.steps(calls) if "secrets" in s[1]])

    def test_the_whole_cluster_goes_back_in_order(self):
        c = self.cluster()
        c.run("run", "--through", "master")
        rc, out, calls = c.run("back")
        self.assertEqual(rc, 0, out[-2000:])
        st = Cluster.steps(calls)
        M = "10.0.0.11"
        # E5 fold: the way back's read-only check (goback-remove5.sh check) comes first; the removal itself after the guard
        self.assertLess(self.index(st, M, "guard.sh on agent"), st.index((M, "goback-remove5.sh")))
        self.assertLess(self.index(st, M, "history-load-4x.sh"), self.index(st, M, "goback-install4.sh --wazuh-server"))
        self.assertLess(self.index(st, "10.0.0.1", "goback-install4.sh --start-cluster"), self.index(st, M, "history-load-4x.sh"))
        self.assertLess(self.index(st, M, "goback-restore-manager.sh master"), self.index(st, "10.0.0.12", "goback-restore-manager.sh worker"))
        self.assertLess(self.index(st, "10.0.0.1", "indexer-security.sh verify4"), self.index(st, M, "retention-4x.sh restore4"))
        self.assertLess(self.index(st, M, "retention-4x.sh restore4"), self.index(st, M, "guard.sh off agent"))
        self.assertTrue(os.path.exists(os.path.join(c.t, "st", "state", "back.done")))
        rc, out, _ = c.run("run")
        self.assertIn("records a finished return to 4.x", out)

    def test_the_master_alone_goes_back_while_the_workers_serve_and_keeps_its_generation(self):
        c = self.cluster()
        c.run("run", "--through", "master")
        rc, out, calls = c.run("back", "master")
        self.assertEqual(rc, 0, out[-2000:])
        st = Cluster.steps(calls)
        M = "10.0.0.11"
        self.assertEqual({n for n, _ in st}, {M})
        self.assertLess(self.index(st, M, "guard.sh on cluster"), self.index(st, M, "goback-install4.sh --wazuh-server wazuh-1"))
        self.assertIn((M, "NO_FILEBEAT=1 goback-restore-manager.sh master") if False else (M, "goback-restore-manager.sh master"), st)
        self.assertLess(self.index(st, M, "guard.sh off cluster"), self.index(st, M, "guard.sh off agent"))
        self.index(st, M, "generation.sh keep")
        self.assertFalse(os.path.exists(os.path.join(c.t, "st", "state", "phase.master")))   # the next run goes forward again
        c.run("run", "--through", "workers")
        rc, out, _ = c.run("back", "master")
        self.assertIn("worker wazuh-2 was already frozen", out)


# =============================================================================================== item 2: no lab values
LAB_ONLY = {"watch-manager.sh", "watch-agent.sh", "import-kill.sh", "import-sigkill.sh", "import-master.sh", "import-finish.sh",
            "crash-during-rpm-post.sh", "fail-service.sh", "agent-guard.sh"}


class NoLabValuesInShippedCodeItem2(unittest.TestCase):
    def shipped(self, tree):
        nd = os.path.join(tree, "cluster", "node")
        files = [os.path.join(nd, f) for f in os.listdir(nd) if f not in LAB_ONLY]
        files += [os.path.join(tree, "cluster", f) for f in os.listdir(os.path.join(tree, "cluster")) if f.endswith(".py")]
        if os.path.exists(os.path.join(tree, "migrate-cluster.sh")):
            files.append(os.path.join(tree, "migrate-cluster.sh"))
        return {f: open(f).read() for f in files if os.path.isfile(f)}

    def test_no_lab_account_path_and_no_development_build_address(self):
        bad = {f: w for f, txt in self.shipped(SRC).items() for w in ("/home/ec2-user", "nightly", "packages-staging", "/root/mig-work") if w in txt}
        self.assertEqual(bad, {})


    def install5(self, tree, dev):
        n = NodeSteps(tree)
        self.addCleanup(n.close)
        v5 = os.path.join(n.env["MIG_HOME"], "v5")
        write(os.path.join(v5, "wazuh-install.sh"), 'echo "ASSISTANT $*" >> %s\n' % n.calls)
        write(os.path.join(v5, "wazuh-install-files.tar"), "t")
        write(n.p("/home/ec2-user/v5/wazuh-install.sh"), 'echo "ASSISTANT $*" >> %s\n' % n.calls)
        write(n.p("/home/ec2-user/v5/wazuh-install-files.tar"), "t")
        if dev:
            write(os.path.join(v5, "artifact_urls.yaml"), "x: y\n")
            write(n.p("/home/ec2-user/v5/artifact_urls.yaml"), "x: y\n")
        rc, out = n.run("install5.sh", "-wi", "node-1")
        return rc, [l for l in n.called().splitlines() if l.startswith("ASSISTANT")]

    def test_the_development_manifest_is_used_only_when_staged(self):
        rc, calls = self.install5(SRC, False)
        self.assertEqual(rc, 0)
        self.assertEqual(calls, ["ASSISTANT -wi node-1 -id"])
        rc, calls = self.install5(SRC, True)
        self.assertEqual(calls, ["ASSISTANT -wi node-1 -id -d local"])


    def agents_argv(self, manifest=None, **env):
        n = NodeSteps(SRC)
        self.addCleanup(n.close)
        fake = os.path.join(n.t, "fsrc")
        for f in ("migrate.sh", "mig_helper.py"):
            shutil.copy(os.path.join(SRC, f), os.path.join(fake, f) if os.path.isdir(fake) else (os.makedirs(fake) or os.path.join(fake, f)))
        argv = os.path.join(n.t, "argv.json")
        write(os.path.join(fake, "fleet-upgrade.py"), "import json, sys\njson.dump(sys.argv[1:], open(%r, 'w'))\n" % argv)
        if manifest:
            write(os.path.join(n.env["MIG_HOME"], "v5", "artifact_urls.yaml"), manifest)
        rc, out = n.run("agents-node.sh", "raw", "status", env=dict(env, SRC=fake))
        self.assertEqual(rc, 0, out)
        return json.load(open(argv)), out

    def test_the_agent_packages_come_from_the_setting_or_the_manifest_never_a_default_address(self):
        a, out = self.agents_argv()
        self.assertNotIn("--wpk-repo", a)
        self.assertIn("the default of the manager", out)
        m = 'wazuh_wpk_agent_x64_windows: "https://pk.example/dev/5.0.0/wpk/windows/wazuh_agent_v5.0.0_windows.wpk"\n' \
            'wazuh_wpk_agent_amd64_deb: "https://pk.example/dev/5.0.0/wpk/linux/deb/amd64/wazuh_agent_v5.0.0_linux_amd64.deb.wpk"\n'
        a, out = self.agents_argv(m)
        self.assertEqual(a[a.index("--wpk-repo") + 1], "pk.example/dev/5.0.0/wpk/")
        a, out = self.agents_argv(m, WPK_REPO="mirror.example/wpk/")
        self.assertEqual(a[a.index("--wpk-repo") + 1], "mirror.example/wpk/")

    def test_a_manifest_naming_two_repositories_is_refused(self):
        H = helpers.load(os.path.join(SRC, "mig_helper.py"), "cl1_helper_wpk")
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        p = write(os.path.join(t, "a.yaml"), 'wazuh_wpk_a: "https://a/wpk/linux/x.wpk"\nwazuh_wpk_b: "https://b/wpk/windows/y.wpk"\n')
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(H.wpk_repo(p), 1)


# =============================================================================================== item 3: deb and rpm
class DebAndRpmNodesItem3(unittest.TestCase):
    def source_check(self, tree):
        n = NodeSteps(tree)
        self.addCleanup(n.close)
        n.stub("apt-get")
        n.stub("dpkg-query", 'case "${@: -1}" in wazuh-indexer) printf "installed 4.14.9-1";; *) exit 1;; esac')
        n.stub("rpm", 'echo "package ${@: -1} is not installed"; exit 1')
        return n.run("source-version.sh", env={"PKGFAM": ""})

    def test_a_deb_node_is_read_from_dpkg(self):
        rc, out = self.source_check(SRC)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("wazuh-indexer 4.14.9-1 on", out)


    def fw(self, tree, code):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        sh.stub("firewall-cmd", "exit 1")
        sh.stub("ufw", 'case "$1" in status) printf "Status: active\\n\\nTo   Action   From\\n1514/tcp   ALLOW   Anywhere\\n1515   ALLOW   Anywhere\\n";; esac; exit 0')
        return sh.run(code), sh.called()

    def test_ufw_is_the_host_firewall_when_active(self):
        (rc, out), calls = self.fw(SRC, 'echo "kind=$(fw_kind) 1514=$(fw_how 1514) 1515=$(fw_how 1515) 1517=$(fw_how 1517)"; fw_port add 1517; fw_close_legacy')
        self.assertIn("kind=ufw 1514=port 1515=port 1517=", out)
        self.assertIn("ufw allow 1517/tcp", calls)
        self.assertIn("ufw delete allow 1514/tcp", calls)
        self.assertIn("ufw delete allow 1515/tcp", calls)


    def test_every_node_step_uses_the_family_aware_queries(self):
        for f in os.listdir(os.path.join(SRC, "cluster", "node")):
            if f.endswith(".sh") and f not in LAB_ONLY and f != "common.sh":   # common.sh holds the family choice itself
                txt = open(os.path.join(SRC, "cluster", "node", f)).read()
                self.assertNotRegex(txt, r"(?m)^[^#]*\brpm -q ", f)


# =============================================================================================== item 4: parity on the master
class SettingsOnAClusterItem4And6(unittest.TestCase):
    """E4-cluster gaps 2a to 2c and rule 21 on order C."""

    def collect(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        v4 = os.path.join(sh.root, "var", "ossec")
        for f in ("etc/ossec.conf", "etc/local_internal_options.conf", "api/configuration/api.yaml", "etc/shared/default/agent.conf"):
            write(os.path.join(v4, f), "<x/>\n")
        os_rel = write(os.path.join(sh.tmp, "os-release"), "ID=rhel\nVERSION_ID=9.6\n")
        return sh.run("( set -e; pc_settings ) > $TMPDIR/pc.out 2>&1; echo \"rc=$?\"; cat $TMPDIR/pc.out", env={"MIG_OS_RELEASE": os_rel, "PKGFAM": "rpm", "TMPDIR": sh.tmp})

    def test_a_manager_only_node_collects_its_settings(self):
        rc, out = self.collect(SRC)
        self.assertIn("rc=0", out)
        self.assertIn("not on this node (a manager-only node of a cluster): /etc/wazuh-indexer/opensearch.yml", out)


    def test_the_first_node_of_order_c_is_checked_alone_and_later_ones_against_it(self):
        mig = open(os.path.join(SRC, "migrate.sh")).read()
        self.assertIn('if [ "$CLUSTER_CANDIDATES" = first-node ]; then', mig)
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        conf = '<ossec_config><cluster><name>wazuh</name><node_name>%s</node_name><node_type>%s</node_type><key>%s</key><port>1516</port><bind_addr>0.0.0.0</bind_addr><nodes><node>10.0.0.11</node></nodes></cluster></ossec_config>'
        m = write(os.path.join(t, "m", "wazuh-manager.conf"), conf % ("wazuh-1", "master", "a" * 32))
        w = write(os.path.join(t, "w", "wazuh-manager.conf"), conf % ("wazuh-2", "worker", "a" * 32))
        cc = os.path.join(SRC, "converter", "cluster_check.py")
        self.assertEqual(subprocess.run([sys.executable, cc, os.path.dirname(m)], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run([sys.executable, cc, os.path.dirname(w), os.path.dirname(m)], capture_output=True).returncode, 0)
        bad = write(os.path.join(t, "b", "wazuh-manager.conf"), conf % ("wazuh-2", "worker", "b" * 32))
        self.assertEqual(subprocess.run([sys.executable, cc, os.path.dirname(bad), os.path.dirname(m)], capture_output=True).returncode, 1)
        self.assertIn('CLUSTER_CANDIDATES="$peers"; im_settings', open(os.path.join(SRC, "cluster", "node", "settings-node.sh")).read())

    def identity_stage(self, tree, **env):
        n = NodeSteps(tree)
        self.addCleanup(n.close)
        write(n.p("/var/wazuh-manager/framework/python/bin/python3"), "#!%s\nprint('GATE PASS (fake stage)')\n" % sys.executable, 0o755)
        n.stub("curl", "exit 0")
        return n.run("identity-stage-master.sh", env=env) + (n.called(),)

    def test_the_masters_settings_are_staged_before_the_identity_steps_restart(self):
        rc, out, calls = self.identity_stage(SRC)
        self.assertNotEqual(rc, 0)
        self.assertIn("the settings stage refused (nothing staged)", out)
        self.assertNotIn("systemctl stop wazuh-manager", calls)       # no restart on settings that were refused


    def test_a_second_attempt_collects_its_own_settings_at_the_export(self):
        txt = open(os.path.join(SRC, "cluster", "node", "export-manager.sh")).read()
        self.assertIn('settings-node.sh" collect4', txt)
        n = NodeSteps(SRC)
        self.addCleanup(n.close)
        for f in ("etc/ossec.conf", "etc/local_internal_options.conf", "api/configuration/api.yaml"):
            write(n.p("/var/ossec/" + f), "<x/>\n")
        os.makedirs(n.p("/var/ossec/etc/shared/default"))
        rc, out = n.run("settings-node.sh", "collect4", env={"MIG_OS_RELEASE": write(os.path.join(n.t, "osr"), "ID=ubuntu\nVERSION_ID=24.04\n")})
        self.assertEqual(rc, 0, out)
        for f in ("ossec.conf", "api.yaml", "stock/SOURCE"):
            self.assertTrue(os.path.exists(os.path.join(n.bundle, "v4", "config", f)), f)

    def test_a_worker_waits_for_its_cluster_daemon_not_for_an_api_it_does_not_run(self):
        for f in ("settings-node.sh", "open-node.sh"):
            txt = open(os.path.join(SRC, "cluster", "node", f)).read()
            self.assertIn("wait_clusterd", txt, f)
            self.assertNotIn("wait_api5", txt.split("apply-worker)")[-1] if f == "settings-node.sh" else txt, f)


class RulesetAndDecisionOnTheMasterItem4(unittest.TestCase):
    def test_the_master_runs_the_all_in_ones_ruleset_and_decision_functions(self):
        txt = open(os.path.join(SRC, "cluster", "node", "ruleset-node.sh")).read()
        for fn in ("pc_ruleset_src && pc_ruleset_build", "im_ruleset", "op_decision"):
            self.assertIn(fn, txt)
        open_ = open(os.path.join(SRC, "cluster", "node", "open-node.sh")).read()
        self.assertLess(open_.index("op_in_force"), open_.index("op_listeners"))

    def test_on_a_cluster_manager_the_indexer_is_the_inventorys(self):
        n = NodeSteps(SRC)
        self.addCleanup(n.close)
        tgz(n.env["V5_TAR"], {"wazuh-install-files/credentials.env": b'WAZUH_INDEXER_ADMIN_PASSWORD="pw5"\n'})
        write(os.path.join(n.node, "probe.sh"), '. "$(dirname "$(readlink -f "$0")")/common.sh"\naio_lib\necho "host=$(idxhost) ca=$IDX5_CA pw=$( [ -n "$(idx5pw)" ] && echo set)"\n', 0o755)
        rc, out = n.run("probe.sh", env={"IDX5_HOST": "10.0.0.1"})
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"host=10\.0\.0\.1 ca=\S*/etc/wazuh-manager/certs/indexer-ca\.pem pw=set")


# =============================================================================================== item 5: the guide's four points
class FoldedAlertsAreShapedWithTheHistoryItem5a(unittest.TestCase):
    """Point a: the alerts folded from each manager's alerts.json went into wazuh-alerts-4.x-YYYY.MM on 5.0, which the
    history's aliases do not cover, unshaped: they did not show in the 5.0 screens. Now they join the history bundle."""

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)
        s = Served(FakeOpenSearch({"wazuh-alerts-4.x-2026.11.20": (1763596800000, 3)}))
        self.addCleanup(s.close)
        self.hist = os.path.join(self.t, "bundle", "history")
        r = subprocess.run([sys.executable, os.path.join(SRC, "dump.py"), "--url", s.url, "--user", "admin", "--password-env", "P",
                            "--out", self.hist, "--workers", "1"], env=dict(os.environ, P="pw", PYTHONDONTWRITEBYTECODE="1"), capture_output=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout)
        lines = [{"timestamp": "2026-11-20T10:00:0%d.000+0000" % i, "id": "17636%d" % i, "rule": {"id": "5501", "level": 3}} for i in range(2)]
        lines.append({"timestamp": "2026-11-21T00:00:01.000+0000", "id": "1763700", "rule": {"id": "5501", "level": 3}})
        self.alerts = write(os.path.join(self.t, "alerts.json"), "".join(json.dumps(x) + "\n" for x in lines))

    def fold(self, label="wazuh-2-v4", off=0):
        out = os.path.join(self.t, "fold", label)
        r = subprocess.run([sys.executable, os.path.join(SRC, "cluster", "alertsjson-fold.py"), "dumpfold", self.alerts, str(off), "wazuh-2", label, out],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([sys.executable, os.path.join(SRC, "cluster", "alertsjson-fold.py"), "merge", out, self.hist], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_the_fold_joins_the_history_bundle_under_its_daily_source_index(self):
        out = self.fold()
        self.assertIn('"merged": 3', out)
        hl = helpers.load(os.path.join(SRC, "history_load.py"), "cl1_hl_fold", extra_path=SRC)
        b = hl.Bundle(self.hist)
        self.assertEqual(b.verify(), (3, []))                                   # the dump's file and the two fold files
        self.assertEqual(b.man["indices"]["wazuh-alerts-4.x-2026.11.20"]["docs_expected"], 5)
        self.assertEqual(b.months["2026.11"]["docs"], 6)
        new = json.load(open(os.path.join(self.hist, "indices", "wazuh-alerts-4.x-2026.11.21.json")))
        self.assertNotIn("creation_date", new)                                  # its age counts from its own day
        ids = [json.loads(l)["_id"] for l in list(gzip.open(os.path.join(self.hist, "data", "wazuh-alerts-4.x-2026.11.21", "fold-wazuh-2-v4-0.ndjson.gz"), "rt"))[0::2]]
        self.assertEqual(ids, ["aj-wazuh-2-1763700"])                           # the way back's bulk file uses the same id
        self.assertIn("history/manifest.json", out)

    def test_a_second_merge_of_the_same_fold_changes_nothing(self):
        self.fold()
        before = open(os.path.join(self.hist, "manifest.json")).read()
        self.assertIn("already in the history bundle", self.fold())
        self.assertEqual(open(os.path.join(self.hist, "manifest.json")).read(), before)


    def test_the_node_step_merges_on_the_master_and_keeps_its_manifest_true(self):
        n = NodeSteps(SRC)
        self.addCleanup(n.close)
        shutil.copytree(self.hist, os.path.join(n.bundle, "history"))
        write(os.path.join(n.bundle, "v4", "filebeat-not-shipped.json"), json.dumps({"filebeat_offset": 0}))
        shutil.copy(self.alerts, write(os.path.join(n.bundle, "v4", "alerts", "alerts.json"), ""))
        subprocess.run("cd %s && find . -type f ! -path './state/*' ! -path './logs/*' ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256" % n.bundle, shell=True)
        rc, out = n.run("fold-alertsjson.sh", "wazuh-1")
        self.assertEqual(rc, 0, out)
        self.assertIn("1 generation(s) folded into the history bundle", out)
        r = subprocess.run("cd %s && sha256sum --quiet -c MANIFEST.sha256" % n.bundle, shell=True, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.exists(os.path.join(n.bundle, "v4", "alertsjson-fold.ndjson.gz")))   # the way back's bulk file


class TheGuidesOtherPointsItem5(unittest.TestCase):
    def test_b_the_agent_guard_is_on_from_before_each_managers_removal_to_its_opening(self):
        mc = open(os.path.join(SRC, "migrate-cluster.sh")).read()
        for who in ("ma", "wk"):
            self.assertLess(mc.index('step %s.guard' % ("master" if who == "ma" else '"workers.$w')), mc.index('step %s.remove4x' % ("master" if who == "ma" else '"workers.$w')))
        self.assertIn("op_listeners", open(os.path.join(SRC, "cluster", "node", "open-node.sh")).read())
        self.assertIn("guard off   # R2", open(os.path.join(SRC, "migrate.sh")).read())

    def test_c_the_way_back_reloads_with_the_shipped_loader_only(self):
        self.assertFalse(os.path.exists(os.path.join(SRC, "cluster", "node", "history-load.sh")))
        for f in os.listdir(os.path.join(SRC, "cluster", "node")):
            self.assertNotIn("tools/load.py", open(os.path.join(SRC, "cluster", "node", f)).read(), f)


# =============================================================================================== item 6: E4-cluster's gaps
class FilebeatRepairComparesWithTheBundleGap1(unittest.TestCase):
    def repair(self, tree):
        n = NodeSteps(tree)
        self.addCleanup(n.close)
        r = os.path.join(n.bundle, "v4", "rollback")
        tgz(os.path.join(r, "etc-filebeat.tar.gz"), {"etc/filebeat/filebeat.yml": b"output.elasticsearch: the site's\n", "etc/filebeat/certs/root-ca.pem": b"CA"})
        tgz(os.path.join(r, "filebeat-keystore.tar.gz"), {"var/lib/filebeat/filebeat.keystore": b"KS"})
        tgz(os.path.join(r, "filebeat-module-wazuh.tar.gz"), {"usr/share/filebeat/module/wazuh/module.yml": b"M"})
        write(n.p("/etc/filebeat/filebeat.yml"), "# the package's own default, 9,982 bytes in the lab\n" * 50)
        n.stub("rpm", "exit 0")
        n.stub("filebeat", 'echo "talk to server... OK"')
        n.stub("systemctl", '[ "$1" = is-active ] && { [ "$2" = -q ] && exit 0; echo active; }; exit 0')
        return n.run("filebeat-repair.sh") + (n,)

    def test_a_package_default_configuration_is_replaced_by_the_bundles(self):
        rc, out, n = self.repair(SRC)
        self.assertEqual(rc, 0, out)
        self.assertEqual(open(n.p("/etc/filebeat/filebeat.yml")).read(), "output.elasticsearch: the site's\n")
        self.assertTrue(os.path.exists(n.p("/etc/filebeat/certs/root-ca.pem")))
        self.assertIn("(differs from the bundle's)", out)
        self.assertIn("/etc/filebeat/certs/root-ca.pem (missing)", out)



class SecretDigestsAreOwnerOnlyGap8(unittest.TestCase):
    def test_mode_600(self):
        for tree, want in ((SRC, 0o600),):
            bs = helpers.load(os.path.join(tree, "bundle_secrets.py"), "cl1_bs_%d" % (want or 0))
            t = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, t, True)
            old = os.umask(0o022)
            try:
                bs.record_digests(t, {"x": "a" * 20})
            finally:
                os.umask(old)
            m = os.stat(os.path.join(t, "state", "secret-digests.json")).st_mode & 0o777
            if want:
                self.assertEqual(m, want)
            else:
                self.assertEqual(m, 0o644)

    def test_the_ca_key_message_does_not_claim_what_the_key_signs(self):
        self.assertNotIn("signs this deployment's certificates", open(os.path.join(SRC, "bundle_secrets.py")).read())


# =============================================================================================== E4-deb (coordinator's addition)
H = helpers.load(os.path.join(SRC, "mig_helper.py"), "cl1_helper")
HL = helpers.load(os.path.join(SRC, "history_load.py"), "cl1_history_load", extra_path=SRC)


class HistoryCompareKnowsTheRetentionNH1(unittest.TestCase):
    def dirs(self, journal):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        fp, t5 = os.path.join(t, "fingerprint"), os.path.join(t, "truth5")
        write(os.path.join(fp, "indices.json"), json.dumps({"wazuh-alerts-4.x-2026.07.01": 302581, "wazuh-alerts-4.x-2026.11.20": 1000, "wazuh-monitoring-x": 4}))
        write(os.path.join(t5, "history.json"), json.dumps({"per_source_index": {"wazuh-alerts-4.x-2026.11.20": 1000}}))
        write(os.path.join(t5, "history_visible.json"), json.dumps({"through_findings_pattern": 1000}))
        if journal is not None:
            write(os.path.join(t, "history", "load-state", "journal.json"), json.dumps({"months": journal}))
        return fp, t5

    def test_months_the_retention_left_out_are_not_lost(self):
        fp, t5 = self.dirs({"2026.07": {"status": "expired-before-load"}, "2026.11": {"status": "loaded"}})
        rows = H.history_rows(fp, t5, False)
        self.assertEqual([r[1] for r in rows], ["CARRIED", "NOT LOADED (retention)", "CARRIED"])
        self.assertIn("302581 alert(s) in 1 index(es) of 2026.07: expired by the retention before the load", rows[1][2])

    def test_a_real_difference_is_still_lost(self):
        fp, t5 = self.dirs({})
        self.assertEqual([r[1] for r in H.history_rows(fp, t5, False)], ["LOST", "LOST"])



class OneDeadlineForTheWholeLoadNF2(unittest.TestCase):
    class Clock:
        t = 0.0

        def now(self):
            return self.t

    def test_a_queued_file_stops_at_once_when_the_indexer_has_been_away_for_the_wait(self):
        c = self.Clock()
        with mock.patch.object(HL, "CLOCK", c.now), mock.patch.object(HL, "SLEEP", lambda s: None), mock.patch.object(HL, "DOWN", HL.Down()), \
                mock.patch("sys.stdout", io.StringIO()):
            HL.not_ready(ConnectionRefusedError(111, "refused"), 0.0, 2, 60, {})        # the first process, at 0 s
            c.t = 61.0
            with self.assertRaises(RuntimeError):                                       # a file queued behind it, its own t0 now
                HL.not_ready(ConnectionRefusedError(111, "refused"), 61.0, 2, 60, {})


    def test_the_summary_is_wall_clock_not_the_sum_of_the_processes(self):
        d = HL.Down()
        d.since(0.0)
        d.since(3.0)                       # a second process, the same outage
        d.answered(18.0)
        d.answered(18.5)                   # the other process sees the answer too: counted once
        self.assertEqual(d.total(), 18.0)

    def test_the_record_is_shared_with_forked_processes(self):
        import multiprocessing
        d = HL.Down(shared=True)
        p = multiprocessing.get_context("fork").Process(target=d.since, args=(5.0,))
        p.start()
        p.join()
        self.assertEqual(d.since(9.0), 5.0)

    def test_the_stop_is_one_line(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        write(os.path.join(t, "manifest.json"), json.dumps({"indices": {}}))

        def boom(*a):
            raise RuntimeError("the indexer did not answer for 60 s (x): the load stops here and resumes with the same command")
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["history_load.py", "apply", "--bundle", t]), mock.patch.object(HL, "cmd_apply", boom), \
                mock.patch.object(HL.hm, "Api", lambda a: None), contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as e:
                HL.main()
        self.assertEqual(e.exception.code, 1)
        self.assertEqual(buf.getvalue().strip().splitlines(), ["ERROR the indexer did not answer for 60 s (x): the load stops here and resumes with the same command"])


class AgentsWaitForABrieflyDisconnectedAgentNF5(unittest.TestCase):
    FU = helpers.load(os.path.join(SRC, "fleet-upgrade.py"), "cl1_fleet")

    def settle(self, mod):
        reads = [[{"id": "004", "status": "disconnected", "lastKeepAlive": "2026-11-25T10:03:20+00:00"}],
                 [{"id": "004", "status": "active", "lastKeepAlive": "2026-11-25T10:04:15+00:00"}]]
        clock = {"t": 0}
        a = mock.Mock(agents=None, groups=None, pending_wait=120)
        kw = {"_now": lambda: 1795600000 + 0} if "_now" in mod.fleet_settled.__code__.co_varnames else {}
        import datetime
        now = datetime.datetime(2026, 11, 25, 10, 3, 42, tzinfo=datetime.timezone.utc).timestamp()
        if kw:
            kw["_now"] = lambda: now
        with mock.patch.object(mod, "fleet", lambda *x: reads.pop(0) if len(reads) > 1 else reads[0]), mock.patch.object(mod, "log", lambda *x: None):
            return mod.fleet_settled(None, a, _sleep=lambda s: clock.__setitem__("t", clock["t"] + s), _clock=lambda: clock["t"], **kw)

    def test_an_agent_disconnected_with_a_recent_keepalive_is_waited_for(self):
        agents, left, waited = self.settle(self.FU)
        self.assertEqual(agents[0]["status"], "active")
        self.assertEqual((left, waited), ([], 10))



class FeedWaitWritesEachLineNF1a(unittest.TestCase):
    def first_output(self, tree):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        import time
        log = write(os.path.join(t, "m.log"), time.strftime("%Y/%m/%d %H:%M:%S") + " wazuh-manager-modulesd: content-updater: INFO: Starting feed download\n")
        o = open(os.path.join(t, "out"), "w")
        p = subprocess.Popen([sys.executable, os.path.join(tree, "mig_helper.py"), "feed-wait", log, "5", "", "1"], stdout=o, stderr=subprocess.STDOUT)
        time.sleep(2)
        seen = open(os.path.join(t, "out")).read()
        p.kill()
        p.wait()
        o.close()
        return seen

    def test_progress_is_in_the_log_while_it_waits(self):
        self.assertIn("feed-wait:", self.first_output(SRC))



# =============================================================================================== E4-rpm (coordinator's addition)
class PhaseEightLetsReloadingAgentsSettleRpm3(unittest.TestCase):
    def test_it_waits_for_an_agent_active_on_4x_then_leaves_the_verdict_to_the_compare(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        write(os.path.join(t, "agents.json"), json.dumps([{"id": "000", "status": "active"}, {"id": "004", "status": "active"}, {"id": "005", "status": "disconnected"}]))
        reads = [[{"id": "004", "status": "disconnected"}], [{"id": "004", "status": "active"}]]

        class Api:
            def __init__(self, pw):
                pass

            def get(self, path):
                return reads.pop(0) if len(reads) > 1 else reads[0]
        clock, buf = {"t": 0}, io.StringIO()
        with mock.patch.object(H, "Api", Api), mock.patch.object(H, "api_password5", lambda: "x"), contextlib.redirect_stdout(buf):
            rc = H.settle_agents(t, "60", _sleep=lambda s: clock.__setitem__("t", clock["t"] + s), _now=lambda: clock["t"])
        self.assertEqual(rc, 0)
        self.assertIn("agent 004 is disconnected (reconnecting, or reloading its new group files)", buf.getvalue())
        self.assertIn("every agent that was active on 4.x is active on 5.0 (waited for 004)", buf.getvalue())
        self.assertIn('settle-agents "$BUNDLE_DIR/truth4"', open(os.path.join(SRC, "migrate.sh")).read())


class BackSecretsShredsOnlyCredentialsRpm4(unittest.TestCase):
    def go(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        w = os.path.join(sh.tmp, "work", "v4-install")
        write(os.path.join(w, "wazuh-install-files.tar"), "pw")
        write(os.path.join(w, "offline", "wazuh-manager-4.14.10-1.x86_64.rpm"), "pkg")
        sh.stub("shred", 'for f in "$@"; do [ -f "$f" ] && rm -f "$f"; done; exit 0')
        sh.stub("python3", "exit 0")
        sh.run("abandoned_secrets")
        return " ".join(l for l in sh.called() if l.startswith("shred"))

    def test_the_package_set_is_deleted_not_shredded(self):
        s = self.go(SRC)
        self.assertIn("wazuh-install-files.tar", s)
        self.assertNotIn(".rpm", s)



class IdentityJournalIsSyncedRpm5(unittest.TestCase):
    def test_each_line_is_on_disk_before_the_stage_goes_on(self):
        for mod, want in ((IS, True),):
            t = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, t, True)
            st = mod.State(t)
            calls = []
            real = os.fsync
            with mock.patch.object(mod.os, "fsync", lambda fd: calls.append(fd) or real(fd)):
                st.journal(event="x")
            self.assertEqual(bool(calls), want, mod)


class WindowsReportKeysRpm6(unittest.TestCase):
    def test_removed_blocks_are_named(self):
        txt = open(os.path.join(SRC, "agent", "agent-conf-5x.ps1")).read()
        self.assertNotIn("$rx -replace '[^a-z_ -]'", txt)
        for k in ("'client_buffer'", "'wodle cis-cat'", "'wodle osquery'"):
            self.assertIn(k, txt)


# =============================================================================================== design decision: raw at the finish
class RawStaysOnUntilTheRulesAreActiveOrAnswered(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)
        self.state = os.path.join(self.t, "state")
        write(os.path.join(self.state, "unclassified.applied"), "verified-none\nraw\n")
        write(os.path.join(self.state, "ruleset.verify_summary"), "verify: REPRODUCED 3, NOT_REPRODUCED 1, NOT_SILENCED 0, NO_SAMPLE 0\n")
        write(os.path.join(self.t, "rwork", "verification.md"), "| 100202 | acmeshop payment refused | NOT_REPRODUCED |\n| 100201 | ok | REPRODUCED |\n")
        write(os.path.join(self.t, "src", "etc", "decoders", "local_decoder.xml"), '<decoder name="acmeshop">\n</decoder>\n')
        self.dec = os.path.join(self.t, "decisions.json")

    def decide(self, mod=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = (mod or H).raw_decision(self.dec, self.state, os.path.join(self.t, "rwork"), os.path.join(self.t, "src"))
        return rc, buf.getvalue()

    def answer(self, a):
        d = json.load(open(self.dec))
        d["unclassified-finish"][0]["action"] = a
        json.dump(d, open(self.dec, "w"))

    def test_refused_without_an_answer_naming_the_rules_and_the_logs(self):
        rc, out = self.decide()
        self.assertEqual(rc, 3)
        self.assertIn("RAW INDEXING NOT SWITCHED OFF", out)
        self.assertIn("rule not active: 100202 | acmeshop payment refused | NOT_REPRODUCED", out)
        self.assertIn("events of these custom decoders would be dropped with raw off: acmeshop", out)
        q = json.load(open(self.dec))["unclassified-finish"][0]
        self.assertEqual((q["id"], q["action"], q["choices"]), ("raw-at-finish", None, ["activated", "keep-raw", "accept-loss"]))

    def test_each_answer_is_followed_and_recorded(self):
        self.decide()
        # E5 fold (E5-aio gap 6): "activated" is checked against rmig's record on the node, so the record shows it here
        write(os.path.join(self.t, "rwork", "work", "state.json"), json.dumps({
            "last_activate": "2026-11-25T14:12:00+00:00", "set_aside": {}, "detectors": {"wazuh4-acmeshop-1": {"id": "d1", "rules": ["s1"]}},
            "resources": {"r1": {"type": "rule", "integration": "wazuh4-acmeshop", "space": "custom", "title": "100202"}}}))
        for a, rc in (("keep-raw", 4), ("accept-loss", 0), ("activated", 0)):
            self.answer(a)
            self.assertEqual(self.decide()[0], rc, a)
            self.assertIn(a, open(os.path.join(self.state, "raw.decision")).read())

    def test_active_rules_need_no_answer(self):
        write(os.path.join(self.state, "unclassified.applied"), "activate\nraw\n")
        self.assertEqual(self.decide()[0], 0)

    def test_the_finish_step_stops_before_switching_off(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        rc, out = sh.run('mkdir -p "$STATE"; printf "verified-none\\nraw\\n" > "$STATE/unclassified.applied"; MIGRATION_DECISIONS=$BUNDLE_DIR/decisions.json; fi_raw_off; echo "rc=$?"')
        self.assertIn("RAW INDEXING NOT SWITCHED OFF", out)
        self.assertIn("rc=3", out)
        self.assertNotIn("policy-unclassified", " ".join(sh.called()))

    def test_without_the_decision_the_finish_switched_off_and_assess_promised_nothing_lost(self):
        self.assertNotIn("so nothing is lost", open(os.path.join(SRC, "migrate.sh")).read())
        self.assertIn('nstep_dec "$MASTER" finish-node.sh raw-off', open(os.path.join(SRC, "migrate-cluster.sh")).read())


# =============================================================================================== PERF1 (coordinator's addition)


class Perf1SnapshotShapesInProcesses(unittest.TestCase):
    def test_procs_defaults_to_the_flows_count(self):
        sc = helpers.load(os.path.join(SRC, "snap_consolidate.py"), "cl1_snap", extra_path=SRC)
        with mock.patch.object(sc.os, "cpu_count", lambda: 8):
            self.assertEqual(sc.default_procs(), 4)
        with mock.patch.object(sc.os, "cpu_count", lambda: 64):
            self.assertEqual(sc.default_procs(), 8)
        with mock.patch.object(sc.os, "cpu_count", lambda: 1):
            self.assertEqual(sc.default_procs(), 1)
        self.assertIn("ProcessPoolExecutor(procs", open(os.path.join(SRC, "snap_consolidate.py")).read())

    def test_the_process_path_shapes_the_same_documents(self):
        sent = {"threads": [], "procs": []}
        src = "wazuh-alerts-4.x-2026.11.20"
        docs = [({"_id": "d%d" % i}, {"timestamp": "2026-11-20T03:04:05.000+0000", "rule": {"id": "5501", "level": 3}, "id": str(i)}) for i in range(5)]
        b = mock.Mock(man={"indices": {src: {"docs_expected": 5}}}, month_of=lambda s: "2026.11")
        a = mock.Mock(cluster_name="wazuh", agent_ids="carried", bulk_docs=100, bulk_bytes=1 << 20, breaker_max=0, breaker_wait_max=60)
        for mode in sent:
            def bulk(api, index, pairs, stats, rejected, brk=None, _m=mode):
                sent[_m].extend(pairs)
                stats["created"] += len(pairs)
            with mock.patch.object(HL, "_docs_of_index", lambda api, s, page: iter(docs)), mock.patch.object(HL, "bulk", bulk), \
                    mock.patch.object(HL.hm, "Api", lambda a: None), mock.patch.object(HL, "load_registry", lambda a: {}):
                if mode == "threads":
                    HL.load_index(a, b, src, {"lock": None, "f": io.StringIO()})
                else:
                    r = HL.load_index_proc(a, b, src)
                    self.assertEqual((r[0], r[1]["docs"], r[2]), (src, 5, ""))
        self.assertEqual(sent["threads"], sent["procs"])


if __name__ == "__main__":
    unittest.main()
