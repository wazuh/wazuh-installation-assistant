"""The F6 fold: the E6 runs (E6-aio, E6-cluster-deb, E6-cluster-rpm) and the follow-ups of
the one-command change, folded into the tool."""
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
from test_e2_cluster import NodeSteps, write
from test_cl1_cluster import Cluster

SRC = helpers.SRC
H = helpers.load(os.path.join(SRC, "mig_helper.py"), "mig_helper_f6")


def quiet(fn, *a):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*a)
    return rc, buf.getvalue()


def bash(code, env=None, timeout=60):
    r = subprocess.run(["bash", "-c", code], env=dict(os.environ, **(env or {})), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return r.returncode, r.stdout.decode(errors="replace")


def assistant(path, version):
    """A stand-in 4.x installation assistant: the lines the tool reads (as the real 4.14.x file writes them)."""
    write(path, '#!/bin/bash\nreadonly wazuh_major="4.14"\nreadonly wazuh_version="%s"\nreadonly filebeat_version="7.10.2-*"\n'
                'echo "assistant %s $*"\n' % (version, version), 0o755)
    return path


class _Node(unittest.TestCase):
    def node(self, tree=SRC, src=None):
        n = NodeSteps(tree, src)
        self.addCleanup(n.close)
        return n


class _C(unittest.TestCase):
    def cluster(self, tree=SRC, **over):
        c = Cluster(tree, **over)
        self.addCleanup(c.close)
        return c

    @staticmethod
    def first(calls, host, text, after=-1):
        for k, x in enumerate(calls):
            if k > after and x.startswith(host + " ") and text in x:
                return k
        return None


# ================================================================================================ 1. 4.14.11
class LatestIs41411Item1(unittest.TestCase):
    """4.14.11 was published on 2026-11-25 (GA 15:19Z): the source gate's minimum moves to it; a newer 4.14.x is
    accepted with a warning."""

    def check(self, mod, rows):
        series, minimum = mod.source_policy()
        return mod.source_versions_check(rows, series, minimum)

    def test_the_minimum_is_41411(self):
        self.assertEqual(H.source_policy(), ("4.14", "4.14.11"))
        m = json.load(open(os.path.join(SRC, "manifest", "builds.json")))
        self.assertEqual(m["source_4x"], ["4.14.11"])





    def test_the_all_in_one_assess_line(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        rc, out = sh.run('echo "validated: $VALIDATED_4X min: $(source_min)"')
        self.assertIn("validated: 4.14.11 min: 4.14.11", out)


class TheAssistantInstallsTheSourcesVersionItem1(unittest.TestCase):
    """E6-aio gap 2, E6-cluster-deb gap 4, E6-cluster-rpm: packages.wazuh.com/4.14/wazuh-install.sh serves only the
    latest 4.14.x; staged for an older source, the way back would reinstall the newer version (E6-cluster-rpm saw a
    4.14.10 master come back as 4.14.11 after a cut way back). The staged assistant must install the source's version."""

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="f6-asst-")
        self.addCleanup(shutil.rmtree, self.t, True)

    def test_the_version_is_read_from_the_file(self):
        self.assertEqual(H.assistant_version(assistant(os.path.join(self.t, "a.sh"), "4.14.11")), "4.14.11")
        write(os.path.join(self.t, "b.sh"), "echo hi\n")
        self.assertIsNone(H.assistant_version(os.path.join(self.t, "b.sh")))


    def test_a_mismatch_is_refused_naming_the_file_to_give(self):
        a = assistant(os.path.join(self.t, "a.sh"), "4.14.12")
        rc, out = quiet(H.v4_assistant_check, a, "4.14.11-1", "V4_ASSISTANT=<path to that file>")
        self.assertEqual(rc, 1)
        self.assertIn("V4 ASSISTANT REFUSED: the 4.x assistant %s installs 4.14.12, but this deployment runs 4.14.11" % a, out)
        self.assertIn("Give the 4.14.11 installation assistant as V4_ASSISTANT=<path to that file>", out)
        self.assertIn("or upgrade the source to 4.14.12 first", out)

    def test_an_older_assistant_is_refused_without_the_upgrade_hint(self):
        a = assistant(os.path.join(self.t, "a.sh"), "4.14.11")
        rc, out = quiet(H.v4_assistant_check, a, "4.14.12-1")
        self.assertEqual(rc, 1)
        self.assertNotIn("upgrade the source", out)

    def test_the_same_version_passes_and_an_unknown_source_is_said(self):
        a = assistant(os.path.join(self.t, "a.sh"), "4.14.11")
        self.assertEqual(quiet(H.v4_assistant_check, a, "4.14.11-1")[0], 0)
        rc, out = quiet(H.v4_assistant_check, a, "")
        self.assertEqual(rc, 0)
        self.assertIn("not on record here", out)

    def test_a_file_with_no_version_is_refused(self):
        write(os.path.join(self.t, "b.sh"), "echo hi\n")
        self.assertEqual(quiet(H.v4_assistant_check, os.path.join(self.t, "b.sh"), "4.14.11-1")[0], 1)



class AllInOneAssistantCheckItem1(unittest.TestCase):
    """migrate.sh: the pre-copy refuses the 4.x assistant of another version before the freeze; removal and the way back
    check the bundle's copy again before running it."""

    def shell(self, tree, mgr="4.14.11-1"):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        sh.stub("dpkg-query", 'case "${@: -1}" in wazuh-manager|wazuh-indexer|wazuh-dashboard) printf "installed %s";; filebeat) printf "installed 7.10.2-2";; *) exit 1;; esac' % mgr)
        sh.stub("apt-get")
        return sh

    def stage(self, tree, version):
        sh = self.shell(tree)
        v4 = assistant(os.path.join(sh.tmp, "in", "v4.sh"), version)
        v5 = write(os.path.join(sh.tmp, "in", "v5.sh"), "echo v5\n")
        rc, out = sh.run('pc_stage; echo "rc=$?"; ls "$BUNDLE_DIR/v4"', env={"V4_ASSISTANT": v4, "V5_ASSISTANT": v5, "V5_ARTIFACT_URLS": "", "V4_PACKAGES_CACHE": "0"})
        return sh, out

    def test_the_precopy_refuses_a_newer_assistant_and_keeps_none(self):
        sh, out = self.stage(SRC, "4.14.12")
        self.assertIn("rc=1", out)
        self.assertIn("V4 ASSISTANT REFUSED", out)
        self.assertIn("V4_ASSISTANT=<path to that file>", out)
        self.assertFalse(os.path.exists(os.path.join(sh.bundle, "v4", "wazuh-install.sh")))

    def test_the_precopy_takes_the_sources_own(self):
        sh, out = self.stage(SRC, "4.14.11")
        self.assertIn("rc=0", out)
        self.assertIn("installs 4.14.11, the source's own version", out)


    def back(self, tree):
        sh = self.shell(tree, mgr="")
        sh.stub("dpkg-query", "exit 1")                                     # 4.x and 5.0 removed: nothing installed
        assistant(os.path.join(sh.bundle, "v4", "wazuh-install.sh"), "4.14.12")
        sh.write("v4/packages.txt", "wazuh-manager 4.14.11-1\nwazuh-indexer 4.14.11-1\nwazuh-dashboard 4.14.11-1\nfilebeat 7.10.2-2\n")
        rc, out = sh.run('bk_install4; echo "rc=$?"', env={"V4_REINSTALLER": "assistant", "V4_PACKAGES_CACHE": "0"})
        return out

    def test_the_way_back_refuses_the_bundles_newer_assistant_before_running_it(self):
        out = self.back(SRC)
        self.assertIn("rc=1", out)
        self.assertIn("installs 4.14.12, but this deployment runs 4.14.11", out)
        self.assertNotIn("reinstalling 4.x", out)



class ClusterAssistantCheckItem1(_Node):
    """The node steps: the pre-copy records the node's 4.x version and checks the staged assistant; the 4.x removal, the
    way back's check (before anything is removed anywhere) and the reinstall refuse one of another version."""

    def setup(self, tree, version, installed="4.14.11-1"):
        n = self.node(tree)
        n.stub("rpm", '[ -n "%s" ] && [ "${@: -1}" = wazuh-indexer ] && { echo %s; exit 0; }; echo "package ${@: -1} is not installed"; exit 1' % (installed, installed))
        assistant(n.p("/home/ec2-user/v4/wazuh-install.sh"), version)
        return n

    def test_the_precopy_check_records_the_version_and_refuses_a_mismatch(self):
        n = self.setup(SRC, "4.14.12")
        rc, out = n.run("source-version.sh", "assistant")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("V4 ASSISTANT REFUSED", out)
        self.assertIn("inputs.v4_assistant in the inventory", out)
        self.assertEqual(open(os.path.join(n.bundle, "state", "v4-source-version")).read().strip(), "4.14.11-1")

    def test_the_precopy_check_passes_the_same_version(self):
        n = self.setup(SRC, "4.14.11")
        rc, out = n.run("source-version.sh", "assistant")
        self.assertEqual(rc, 0, out)

    def test_removal_refuses_before_running_the_assistant(self):
        n = self.setup(SRC, "4.14.12")
        rc, out = n.run("remove4x.sh")
        self.assertNotEqual(rc, 0)
        self.assertIn("not removing 4.x with an assistant of another version", out)
        self.assertNotIn("assistant 4.14.12 -u", out)


    def test_the_way_back_check_refuses_from_the_record_once_4x_is_gone(self):
        n = self.setup(SRC, "4.14.12", installed="")
        write(os.path.join(n.bundle, "state", "v4-source-version"), "4.14.11-1\n")
        write(n.p("/home/ec2-user/v5/wazuh-install.sh"), "x\n")
        write(n.env["V4_TAR"], "x")
        rc, out = n.run("goback-remove5.sh", "check", "indexer")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("REFUSED: the 4.x assistant", out)
        self.assertIn("nothing was removed", out)
        rc, out = n.run("goback-install4.sh", "--wazuh-indexer", "node-1")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("not reinstalling 4.x with an assistant of another version", out)



class ClusterInputsStagedAgainItem4(_C):
    """E6-cluster-deb fix 01 and gap 1: the inputs went to the nodes once, at the pre-copy; an input corrected in the
    inventory afterwards never reached them. Before a node step that reads an input, it is staged again when the
    inventory's value or the file it names changed; and the pre-copy checks the 4.x assistant on every node."""
    I1, M = "10.0.0.1", "10.0.0.11"

    def test_the_precopy_checks_the_assistant_on_every_node(self):
        c = self.cluster()
        rc, out, calls = c.run("run", "--through", "precopy")
        self.assertEqual(rc, 0, out[-2000:])
        for a in ("10.0.0.1", "10.0.0.2", "10.0.0.11", "10.0.0.12", "10.0.0.21"):
            self.assertIsNotNone(self.first(calls, a, "source-version.sh assistant"), a)

    def changed_then_indexers(self, tree):
        c = self.cluster(tree)
        rc, out, _ = c.run("run", "--through", "precopy")
        self.assertEqual(rc, 0, out[-2000:])
        write(c.inv["inputs"]["v4_assistant"], "corrected\n")
        rc, out, calls = c.run("run", "--through", "indexers")
        return rc, out, calls

    def test_a_corrected_assistant_is_staged_again_before_the_removal(self):
        rc, out, calls = self.changed_then_indexers(SRC)
        self.assertEqual(rc, 0, out[-2000:])
        put = self.first(calls, self.I1, "v4/wazuh-install.sh.part")
        rm = self.first(calls, self.I1, "remove4x.sh")
        self.assertIsNotNone(put, calls)
        self.assertLess(put, rm)
        self.assertIn("inputs.v4_assistant changed in the inventory since it was staged here: staged again", out)
        self.assertIsNone(self.first(calls, self.I1, "v5/wazuh-install.sh.part"))    # unchanged inputs are not sent again


    def test_a_url_is_not_fetched_again_while_it_is_unchanged(self):
        c = self.cluster()
        c.inv["inputs"]["v4_assistant"] = "https://packages.example/4.14/wazuh-install.sh"
        c.save()
        c.run("run", "--through", "precopy")
        rc, out, calls = c.run("run", "--through", "indexers")
        self.assertIsNone(self.first(calls, self.I1, "packages.example"))


# ================================================================================================ 2. rmig follow-up questions
RMIG = helpers.env_dir("MIG_TEST_RMIG_DIR")                  # the real rmig (see helpers.needs)
STOCK = helpers.env_dir("MIG_TEST_STOCK_RULESET")           # the 4.14.10 stock ruleset (see helpers.needs)
NEEDS_RULESET = helpers.needs(rmig=RMIG, stock=STOCK)         # the real rmig on the stock ruleset
RM2_RULE = """<group name="acme-audit,audit,">
  <rule id="100500" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">acme-archive</field>
    <description>ACME: archive created via tar.</description>
    <mitre>
      <id>T1560</id>
    </mitre>
  </rule>
</group>
"""
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


@NEEDS_RULESET
class RmigFollowUpQuestionsItem2(unittest.TestCase):
    """E6-aio gap 1 (RM2): rule 100500 on the stock auditd rule, covered by a stock 5.0 rule. Answered "migrate", rmig's
    plan opens a question that did not exist before (fields/audit.key, required). It stayed in rmig's own decisions.json,
    the ruleset step was marked done and the rule was silently left out. Now every question rmig leaves open reaches the
    one decisions file and the step stays open until it is answered."""

    def shell(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        b = os.path.join(sh.bundle, "ruleset-src")
        write(os.path.join(b, "etc", "ossec.conf"), OSSEC_CONF)
        write(os.path.join(b, "etc", "rules", "local_rules.xml"), RM2_RULE)
        os.makedirs(os.path.join(b, "etc", "decoders"))
        os.makedirs(os.path.join(b, "etc", "lists"))
        os.symlink(STOCK, os.path.join(b, "ruleset"))
        return sh

    def build(self, sh, env=None):
        e = {"RMIG_DIR": RMIG}
        e.update(env or {})
        rc, out = sh.run('MIGRATION_DECISIONS=$BUNDLE_DIR/decisions.json; ruleset_build "$BUNDLE_DIR/ruleset-migration" 5.0; echo "rc=$?"', env=e, timeout=120)
        return int(re.findall(r"rc=(\d+)", out)[-1]), out

    def flow(self, sh):
        return json.load(open(os.path.join(sh.bundle, "decisions.json")))

    def set_flow(self, sh, d):
        write(os.path.join(sh.bundle, "decisions.json"), json.dumps(d))

    def first_answers(self, sh):
        rc, out = self.build(sh)
        self.assertIn(rc, (1, 3), out)          # F7: a step that asks exits 3 (1 before)
        d = self.flow(sh)
        r = d["ruleset"]
        self.assertIn("100500", r["covered"])
        r["stock"]["rule:80700"].update(integration="auditd", selection="wazuh.integration.name: auditd")
        r["covered"]["100500"]["action"] = "migrate"
        r["review"] = "accepted"
        self.set_flow(sh, d)
        return self.build(sh)

    def built(self, sh):
        return [f for _, _, fs in os.walk(os.path.join(sh.bundle, "ruleset-migration", "out")) for f in fs if f == "100500.json"]

    def test_the_new_question_reaches_the_flow_file_and_the_step_stays_open(self):
        sh = self.shell(SRC)
        rc, out = self.first_answers(sh)
        self.assertEqual(rc, 3, out)            # F7: a step that asks exits 3, never a failure
        self.assertIn("RULESET QUESTIONS OPEN", out)
        self.assertIn("rule:100500", out)
        self.assertIn("RM-F-UNMAPPED audit.key", out)
        r = self.flow(sh)["ruleset"]
        self.assertIsNone(r["fields"]["audit.key"]["action"])           # asked, never answered for the user
        self.assertEqual(r["covered"]["100500"]["action"], "migrate")   # the user's answers kept as written
        self.assertEqual(r["review"], "accepted")
        self.assertEqual(self.built(sh), [])

    def test_once_answered_the_rule_is_built(self):
        sh = self.shell(SRC)
        self.first_answers(sh)
        d = self.flow(sh)
        d["ruleset"]["fields"]["audit.key"].update(action="map", wcs="rule.name")
        self.set_flow(sh, d)
        rc, out = self.build(sh)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("RULESET QUESTIONS OPEN", out)
        self.assertEqual(self.built(sh), ["100500.json"])

    def test_a_file_of_the_users_own_gets_the_question(self):
        sh = self.shell(SRC)
        rc, out = self.build(sh)
        own = write(os.path.join(sh.tmp, "own.json"), json.dumps(self.flow(sh)["ruleset"]))
        d = json.load(open(own))
        d["stock"]["rule:80700"].update(integration="auditd", selection="wazuh.integration.name: auditd")
        d["covered"]["100500"]["action"] = "migrate"
        d["review"] = "accepted"
        write(own, json.dumps(d))
        rc, out = self.build(sh, {"RMIG_DECISIONS": own})
        self.assertEqual(rc, 3, out)
        self.assertIn("audit.key", json.load(open(own))["fields"])
        self.assertIn(own, out)



# ================================================================================================ 3. one decisions file
from test_cl1_cluster import FAKE_SSH  # noqa: E402

FAKE_SSH_PUSH = FAKE_SSH.replace('[ -t 0 ] || cat > /dev/null', 'if [[ "$*" == *decisions.json.part* ]]; then cat > "$PUSHED.$host"; else [ -t 0 ] || cat > /dev/null; fi')
assert FAKE_SSH_PUSH != FAKE_SSH


class OneDecisionsFileOnAClusterItem3(_C):
    """U1: on a cluster the ruleset questions (the review included) were answered in cluster-state/decisions/<master>.json
    while every other question is in the controller's decisions.json (/root/wazuh-migration-cluster/ for the one
    command). The ruleset section is now answered in the controller's file and carried to the master behind the scenes."""
    M = "10.0.0.11"
    NODE_FILE = {"settings": {}, "ruleset": {"version": 1, "covered": {"100500": {"action": None, "stock_rule": "x"}}, "review": None}}

    def cluster(self, tree=SRC, **over):
        c = super().cluster(tree, **over)
        write(os.path.join(c.t, "fakessh"), FAKE_SSH_PUSH, 0o755)
        c.env["PUSHED"] = os.path.join(c.t, "pushed")
        return c

    def precopy(self, c, node_file):
        return c.run("run", "--through", "precopy", DECISIONS=json.dumps(node_file), FAIL_PAT="ruleset-node.sh precopy", FAIL_RC="3")

    def test_the_review_is_asked_in_the_controllers_file(self):
        c = self.cluster()
        rc, out, calls = self.precopy(c, self.NODE_FILE)
        self.assertNotEqual(rc, 0)
        cdec = json.load(open(os.path.join(c.t, "decisions.json")))
        self.assertIn("review", cdec["ruleset"])
        self.assertIsNone(cdec["ruleset"]["review"])
        self.assertNotIn("ruleset", json.load(open(os.path.join(c.t, "st", "decisions", "wazuh-1.json"))))
        self.assertIn('in %s (node wazuh-1\'s under "nodes", "wazuh-1"; the ruleset questions, the review included, in section "ruleset")' % os.path.join(c.t, "decisions.json"), out)   # F7 wording
        self.assertIn("DECISIONS_SHOWN=", " ".join(calls))

    def test_the_answer_reaches_the_master_and_is_kept(self):
        c = self.cluster()
        self.precopy(c, self.NODE_FILE)
        p = os.path.join(c.t, "decisions.json")
        d = json.load(open(p))
        d["ruleset"]["review"] = "accepted"
        d["ruleset"]["covered"]["100500"]["action"] = "migrate"
        write(p, json.dumps(d))
        node_after = {"settings": {}, "ruleset": dict(d["ruleset"], fields={"audit.key": {"action": None, "required": True}})}
        rc, out, calls = self.precopy(c, node_after)
        pushed = json.load(open(os.path.join(c.t, "pushed." + self.M)))
        self.assertEqual(pushed["ruleset"]["review"], "accepted")
        self.assertEqual(pushed["ruleset"]["covered"]["100500"]["action"], "migrate")
        after = json.load(open(p))["ruleset"]
        self.assertEqual(after["review"], "accepted")                  # the person's answers stay as written
        self.assertIsNone(after["fields"]["audit.key"]["action"])      # the master's new question reaches the same file


    def test_the_helper_keeps_the_answers_and_adds_new_entries(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        cdec, node, out = (os.path.join(t, x) for x in ("c.json", "n.json", "o.json"))
        write(cdec, json.dumps({"point-of-no-return": [], "ruleset": {"review": "accepted", "covered": {"1": {"action": "migrate"}}}}))
        write(node, json.dumps({"settings": {"a": 1}}))
        self.assertEqual(quiet(H.ruleset_carry, "to-node", cdec, node, out)[0], 0)
        self.assertEqual(json.load(open(out)), {"settings": {"a": 1}, "ruleset": {"review": "accepted", "covered": {"1": {"action": "migrate"}}}})
        write(node, json.dumps({"settings": {"a": 1}, "ruleset": {"review": None, "covered": {"1": {"action": None}}, "fields": {"k": {"action": None}}}}))
        quiet(H.ruleset_carry, "from-node", cdec, node)
        self.assertEqual(json.load(open(cdec))["ruleset"], {"review": "accepted", "covered": {"1": {"action": "migrate"}}, "fields": {"k": {"action": None}}})
        self.assertEqual(json.load(open(node)), {"settings": {"a": 1}})


# ================================================================================================ 4. deb gaps 2 and 3
BAD_V5 = """nodes:
  indexer:
    - name: node-1
      ip: "10.0.0.256"
    - name: node-2
      ip: "10.0.0.2"
  manager:
    - name: wazuh-1
      ip: "10.0.0.11"
      node_type: master
    - name: wazuh-2
      ip: "10.0.0.12"
      node_type: worker
  dashboard:
    - name: dashboard
      ip: "10.0.0.21"
"""


class V5ConfigCheckedBeforeRemovalItem4(_C):
    """E6-cluster-deb gap 2: -g runs after the 4.x indexers and the dashboard are removed; an address it refused
    ("Invalid IP in field ip for indexer node node-1: 198.51.100.10") left the cluster with no indexer. The 5.0
    config.yml is checked against the inventory at assess, on every run, before anything is removed."""

    def run_with(self, tree, text):
        c = self.cluster(tree)
        write(c.inv["inputs"]["v5_config"], text)
        return c.run("run", "--through", "indexers")

    def test_a_bad_address_stops_assess_and_nothing_is_removed(self):
        rc, out, calls = self.run_with(SRC, BAD_V5)
        self.assertNotEqual(rc, 0)
        self.assertIn("indexer node node-1: '10.0.0.256' is not a valid IP address", out)
        self.assertFalse(any("remove4x.sh" in c for c in calls))

    def test_a_node_of_the_inventory_missing_is_refused(self):
        rc, out, calls = self.run_with(SRC, BAD_V5.replace('10.0.0.256', '10.0.0.1').replace("    - name: wazuh-2\n      ip: \"10.0.0.12\"\n      node_type: worker\n", ""))
        self.assertNotEqual(rc, 0)
        self.assertIn("node wazuh-2 (worker in the inventory) is not in the 5.0 config.yml", out)

    def test_a_good_file_passes(self):
        rc, out, calls = self.run_with(SRC, BAD_V5.replace('10.0.0.256', '10.0.0.1'))
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("the 5.0 config.yml names every node of the inventory with a valid address", out)

    def test_the_deb_runs_own_files(self):
        nf = helpers.load(os.path.join(SRC, "next_flow.py"), "next_flow_f6")



class RunStepRecordsTheExitCodeItem4(_Node):
    """E6-cluster-deb gap 3 (R1): the node-side follower outlived the killed controller, collected the exit code and
    removed the pid file, so the rerun started the step again. The exit code stays on the node; when the controller's
    own step was cut, a node step that ended with exit 0 is reported and not started again."""

    def setup(self, tree):
        n = self.node(tree)
        write(os.path.join(n.node, "count.sh"), '#!/usr/bin/env bash\necho run >> "$COUNT"\necho "the step ran"\nexit "${STEP_RC:-0}"\n', 0o755)
        n.env["COUNT"] = os.path.join(n.t, "count")
        n.env["RUN_STEP_POLL"] = "0.2"
        return n

    def runs(self, n):
        return open(n.env["COUNT"]).read().count("run") if os.path.exists(n.env["COUNT"]) else 0

    def follower_gone(self, n):
        rc, out = n.run("run-step.sh", "master.install5.count", "count.sh")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(os.path.join(n.bundle, "logs", "steps", "master.install5.count.pid")))   # collected
        return n.run("run-step.sh", "master.install5.count", "count.sh", env={"RUN_STEP_RESUME": "1"})

    def test_a_cut_step_reports_the_finished_node_step(self):
        n = self.setup(SRC)
        rc, out = self.follower_gone(n)
        self.assertEqual(rc, 0, out)
        self.assertIn("finished on this node with exit 0 during the controller's earlier, cut run: not started again", out)
        self.assertEqual(self.runs(n), 1)

    def test_a_failed_one_is_started_again(self):
        n = self.setup(SRC)
        n.env["STEP_RC"] = "4"
        n.run("run-step.sh", "x.count", "count.sh")
        rc, out = n.run("run-step.sh", "x.count", "count.sh", env={"RUN_STEP_RESUME": "1"})
        self.assertEqual(rc, 4)
        self.assertEqual(self.runs(n), 2)

    def test_a_fresh_call_starts_it_again(self):
        n = self.setup(SRC)
        n.run("run-step.sh", "x.count", "count.sh")
        n.run("run-step.sh", "x.count", "count.sh")
        self.assertEqual(self.runs(n), 2)


    def test_the_controller_passes_the_cut(self):
        c = Cluster(SRC)
        self.addCleanup(c.close)
        rc, out, _ = c.run("run", "--through", "precopy")
        self.assertEqual(rc, 0, out[-2000:])
        with open(os.path.join(c.t, "st", "journal.ndjson"), "a") as f:
            f.write(json.dumps({"ts": "2026-11-25T16:49:05Z", "step": "indexers.remove4x", "event": "begin", "detail": "x"}) + "\n")
        rc, out, calls = c.run("run", "--through", "indexers")
        self.assertEqual(rc, 0, out[-2000:])
        rm = [x for x in calls if "remove4x.sh" in x]
        gen = [x for x in calls if "install5.sh -g" in x]
        self.assertTrue(rm and all("RUN_STEP_RESUME=1" in x for x in rm), rm)
        self.assertTrue(gen and not any("RUN_STEP_RESUME" in x for x in gen), gen)


# ================================================================================================ 5. E6-aio gaps 3, 4, 6, 7, 8; GCP
from unittest import mock  # noqa: E402


class KeepRawReadsThePolicyItem5(unittest.TestCase):
    """E6-aio gap 4 (D8): "keep-raw" printed "RAW INDEXING KEPT ON" without reading or setting the policy, and
    policy-unclassified with any word but get and on switched raw indexing off."""

    def fake_idx(self, on):
        calls = []

        def idx(method, path, pw, body=None, **k):
            calls.append((method, path, body))
            if method == "POST":
                return 200, {"hits": {"hits": [{"_source": {"document": {"index_unclassified_events": on, "enabled": True}}}]}}
            return 200, {}
        return idx, calls

    def run_action(self, mod, action, on):
        idx, calls = self.fake_idx(on)
        with mock.patch.object(mod, "idx", idx), mock.patch.object(mod, "idx_password5", lambda: "x"):
            rc, out = quiet(mod.policy_unclassified, action)
        return rc, out, [c for c in calls if c[0] == "PUT"]

    def test_an_unknown_word_changes_nothing(self):
        rc, out, puts = self.run_action(H, "show", True)
        self.assertEqual(rc, 2)
        self.assertEqual(puts, [])
        self.assertIn("unknown action 'show'", out)


    def test_keep_reads_it_back_and_switches_it_on_when_off(self):
        rc, out, puts = self.run_action(H, "keep", True)
        self.assertEqual((rc, puts), (0, []))
        self.assertIn("raw indexing is on (read back): kept", out)
        rc, out, puts = self.run_action(H, "keep", False)
        self.assertEqual(rc, 0)
        self.assertEqual(puts[0][2]["resource"]["index_unclassified_events"], True)
        self.assertIn("was OFF although the answer keeps it on: switched on again", out)

    def finish_keep_raw(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        fake = write(os.path.join(sh.tmp, "helper.sh"), '#!/usr/bin/env bash\necho "HELPER $*" >> %s\ncase "$1" in raw-decision) exit 4;; esac\nexit 0\n' % sh.calls, 0o755)
        sh.write("state/unclassified.applied", "verified-none\nraw\n")
        rc, out = sh.run('python3() { if [ "$1" = "$HELPER" ]; then shift; "%s" "$@"; else command python3 "$@"; fi; }; fi_raw_off; echo "rc=$?"' % fake)
        return out, "\n".join(sh.called())

    def test_the_finish_reads_the_policy_on_keep_raw(self):
        out, calls = self.finish_keep_raw(SRC)
        self.assertIn("HELPER policy-unclassified keep", calls)
        self.assertIn("read back from the standard policy", out)



class EnrollmentTokensWordingItem5(unittest.TestCase):
    """E6-aio gap 3 (R10): the steps said to give the password to agents that enroll; 5.0 agents enroll with tokens
    (1515 is closed after the finish): with use_password yes, tokens made without a credential are refused."""

    def test_the_phase_8_row_and_the_assess_note_say_tokens_with_a_credential(self):
        row = H.enrollment_off_row({"use_password": "no", "authd_pass_sha256": "x"})
        self.assertIn("--create-enrollment-token", row)
        self.assertIn("tokens made with --no-credential stop working", row)
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        rc, out = sh.run("enrollment_off_note 1")
        self.assertIn("mint them with a credential (wazuh-manager-authd --create-enrollment-token, without --no-credential)", out)
        self.assertNotIn("give it to every agent", out)



class RmigCommandLinesLoggedItem5(unittest.TestCase):
    """E6-aio gap 6 (RM3): rmig's command lines (with --engine-limit) were not in any log."""

    def call(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        r = os.path.join(sh.tmp, "rmigdir")
        write(os.path.join(r, "rmig", "__init__.py"), "")
        write(os.path.join(r, "rmig", "__main__.py"), "import sys\nprint('fake rmig', sys.argv[1:])\n")
        rc, out = sh.run('idx5pw() { echo not-a-real-secret-f6; }; rmig apply --workdir /w --engine-limit max_detectors=20 > "$LOGS/rmig-5-apply.log" 2>&1; '
                         'cat "$LOGS/rmig-5-apply.log"; echo ---; cat "$LOGS/rmig-commands.log"', env={"RMIG_DIR": r})
        return out

    def test_the_command_line_is_logged_without_the_password(self):
        out = self.call(SRC)
        self.assertIn("# rmig apply --workdir /w --engine-limit max_detectors=20", out)
        self.assertRegex(out, r"---\n\[[0-9T:Z-]+\] rmig apply --workdir /w --engine-limit max_detectors=20")
        self.assertNotIn("not-a-real-secret-f6", out)



@NEEDS_RULESET
class AssessRulesetBlockWithTheAnswersItem5(unittest.TestCase):
    """E6-aio gap 7: assess's ruleset block was a plan of the live content without the answers: a covered rule answered
    "migrate" was still listed as covered."""

    def assess(self, tree):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        v4 = os.path.join(sh.root, "var", "ossec")
        write(os.path.join(v4, "etc", "ossec.conf"), OSSEC_CONF)
        write(os.path.join(v4, "etc", "rules", "local_rules.xml"), RM2_RULE)
        os.makedirs(os.path.join(v4, "etc", "decoders"))
        os.makedirs(os.path.join(v4, "etc", "lists"))
        os.symlink(STOCK, os.path.join(v4, "ruleset"))
        write(os.path.join(sh.bundle, "decisions.json"), json.dumps({"ruleset": {"version": 1, "covered": {"100500": {"action": "migrate"}},
                                                                                   "stock": {"rule:80700": {"integration": "auditd", "selection": "wazuh.integration.name: auditd"}}}}))
        rc, out = sh.run("assess_ruleset", env={"RMIG_DIR": RMIG, "MIGRATION_DECISIONS": os.path.join(sh.bundle, "decisions.json")}, timeout=120)
        return out

    def test_a_rule_answered_migrate_is_not_listed_as_covered(self):
        out = self.assess(SRC)
        self.assertIn("with your answers in", out)
        self.assertNotIn("rule 100500: stock rule", out)



class MapTagsAndGcpItem5(unittest.TestCase):
    """E6-aio gap 8: wazuh.rule.tags carried " WEF" with its leading blank from the 4.x group list. PR1: the GCP DNS
    conditions r094/r095 matched one lab project only."""

    def mapper(self, tree, name):
        lm = helpers.load(os.path.join(tree, "loader_map.py"), name, extra_path=tree)
        return lm.LoaderMapper(spec=json.load(open(os.path.join(tree, "history-loader-map.json"))))

    ALERT = {"timestamp": "2026-11-25T17:00:00.000+0000", "rule": {"id": "67027", "level": 3, "groups": ["windows", " WEF"], "description": "x"},
             "agent": {"id": "001", "name": "w"}, "manager": {"name": "m"}, "id": "1", "location": "EventChannel"}
    GCP = {"timestamp": "2026-11-25T17:00:00.000+0000", "rule": {"id": "65004", "level": 3, "groups": ["gcp"], "description": "x"},
           "agent": {"id": "000", "name": "m"}, "manager": {"name": "m"}, "id": "2", "location": "gcp",
           "data": {"gcp": {"logName": "projects/acme-prod-42/logs/dns.googleapis.com%2Fdns_queries", "jsonPayload": {"queryName": "example.com."}}}}

    def test_tags_are_trimmed(self):
        out = self.mapper(SRC, "lm_f6").convert(json.loads(json.dumps(self.ALERT)))
        self.assertEqual(out["wazuh"]["rule"]["tags"], ["windows", "WEF"])


    def test_any_gcp_project_gets_the_dns_action(self):
        out = self.mapper(SRC, "lm_f6b").convert(json.loads(json.dumps(self.GCP)))
        self.assertEqual(out["event"]["action"], "dns-query")
        self.assertEqual(out["event"]["category"], ["network"])


    def test_the_manifest_pins_the_new_map(self):
        import hashlib
        m = json.load(open(os.path.join(SRC, "manifest", "builds.json")))["field_map"]
        self.assertEqual(m["sha256"], hashlib.sha256(open(os.path.join(SRC, "history-loader-map.json"), "rb").read()).hexdigest())


# ================================================================================================ 6. one-command follow-ups
FAKE_SSH_LEGACY = FAKE_SSH.replace('  *"cat "*decisions.json*)', '  *"cat "*legacy.open*) echo "$LEGACY_OPEN";;\n  *"cat "*decisions.json*)')
assert FAKE_SSH_LEGACY != FAKE_SSH


class NeverConnectedOnlyFinishesOnAClusterItem6(_C):
    """U1: a cluster whose only agents below 5.0 never connected: the controller's legacy.open did not say why, so the one
    command waited (exit 4) instead of ending as the all-in-one does. The master's reason is carried."""

    def finish(self, tree):
        c = self.cluster(tree)
        write(os.path.join(c.t, "fakessh"), FAKE_SSH_LEGACY, 0o755)
        rc, out, _ = c.run("run")
        self.assertEqual(rc, 0, out[-2000:])
        c.run("confirm-no-return")
        c.run("agents")
        c.run("finish", FAIL_PAT="finish-node.sh legacy-decide", FAIL_RC="3", LEGACY_OPEN="keep never-connected: 002 ")
        return open(os.path.join(c.t, "st", "state", "legacy.open")).read()

    def test_the_masters_reason_is_kept(self):
        self.assertTrue(self.finish(SRC).startswith("keep never-connected: 002"))





class AskIsAQuestionItem6(unittest.TestCase):
    """U1: UNCLASSIFIED_DECISION=ask stopped before the opening with no entry in the decisions file, so the one command
    reported it as a failure. It is now a question in the decisions file, and its answer is the decision."""

    def decide(self, tree, answer=None):
        sh = helpers.Shell(os.path.join(tree, "migrate.sh"))
        self.addCleanup(sh.close)
        dec = os.path.join(sh.bundle, "decisions.json")
        if answer:
            write(dec, json.dumps({"unclassified-decision": [{"id": "unclassified-decision", "action": answer}]}))
        sh.write("state/ruleset.verify_rc", "1\n")
        rc, out = sh.run('op_decision; echo "rc=$?"; cat "$STATE/unclassified.applied" 2>/dev/null', env={"UNCLASSIFIED_DECISION": "ask", "MIGRATION_DECISIONS": dec})
        return out, (json.load(open(dec)) if os.path.exists(dec) else {})

    def test_the_question_is_in_the_decisions_file(self):
        out, d = self.decide(SRC)
        self.assertIn("rc=3", out)
        e = d["unclassified-decision"][0]
        self.assertIsNone(e["action"])
        nf = helpers.load(os.path.join(SRC, "next_flow.py"), "next_flow_f6q")
        self.assertEqual(nf.open_questions(d)[0][0], "unclassified-decision")

    def test_the_answer_is_the_decision(self):
        out, d = self.decide(SRC, "accept")
        self.assertIn("UNCLASSIFIED_DECISION=ask answered in", out)
        self.assertIn("rc=0", out)
        self.assertIn("accept", out.split("rc=0")[-1])

    def test_a_wrong_answer_is_refused(self):
        out, d = self.decide(SRC, "maybe")
        self.assertIn("unknown part \"maybe\"", out)
        self.assertNotIn("rc=0", out)



# ================================================================================================ 7. cosmetic
class RawFinishSummaryIsRmigsLatestItem7(unittest.TestCase):
    """E6-aio gap 5: the raw-at-finish refusal printed the import's verify counts after rmig's own verify had changed
    them (5/1 after the forced rule was built by hand)."""
    VMD = ("# Verification\n\nRun 2026-11-25T17:40:00+00:00 with rmig 0.1.0.\n\n| Result | Rules |\n|---|---:|\n| `REPRODUCED` | 5 |\n"
           "| `NOT_REPRODUCED` | 1 |\n| `NO_SAMPLE` | 1 |\n\n| 4.x rule | Result |\n|---|---|\n| 100300 | `NOT_REPRODUCED` | x |\n")

    def refuse(self, mod):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        state, rwork = os.path.join(t, "state"), os.path.join(t, "rwork")
        write(os.path.join(rwork, "verification.md"), self.VMD)
        write(os.path.join(state, "ruleset.verify_summary"), "verify: REPRODUCED 4, NOT_REPRODUCED 1, NO_SAMPLE 1\n")
        write(os.path.join(state, "unclassified.applied"), "verified-none\nraw\n")
        return quiet(mod.raw_decision, os.path.join(t, "decisions.json"), state, rwork, "")

    def test_the_latest_counts_are_printed(self):
        rc, out = self.refuse(H)
        self.assertEqual(rc, 3)
        self.assertIn("verify: REPRODUCED 5, NOT_REPRODUCED 1, NO_SAMPLE 1 (rmig's verification.md, run 2026-11-25T17:40:00+00:00)", out)



# ================================================================================================ E6-cluster-rpm
class BackMasterGateNeedsTheWorkersConnectedRpmA(_C):
    """E6-cluster-rpm A: the master went back as 4.14.11 beside a 4.14.10 worker (error 3031, the worker could not
    join) and `back master` reported success: its gate compared the two client.keys files only. Every worker must also be
    connected to the master (cluster_control -l). (The version mismatch itself is now refused: item 1.)"""

    def back_master(self, tree, cc=None):
        c = self.cluster(tree)
        rc, out, _ = c.run("run", "--through", "master")
        self.assertEqual(rc, 0, out[-2000:])
        env = {"REGISTRY_TRIES": "2", "REGISTRY_WAIT": "0"}
        if cc is not None:
            env["CLUSTER_CONTROL"] = cc
        return c.run("back", "master", **env)

    def test_a_worker_not_connected_keeps_the_guard_on(self):
        rc, out, calls = self.back_master(SRC, "NAME TYPE VERSION ADDRESS\\nwazuh-1 master 4.14.11 10.0.0.11\\n")
        self.assertNotEqual(rc, 0)
        self.assertIn("worker(s) not connected to the master: wazuh-2", out)
        self.assertFalse(any("guard.sh off agent" in x for x in calls))

    def test_connected_workers_pass(self):
        rc, out, calls = self.back_master(SRC)
        self.assertEqual(rc, 0, out[-2000:])
        self.assertIn("every worker is connected to the master", out)



ASSISTANT5 = r"""#!/usr/bin/env bash
echo "assistant5 $*" >> "$FAKE/assistant.calls"
over=0; for a in "$@"; do [ "$a" = -o ] && over=1; done
if [ -e "$FAKE/installed-wazuh-manager" ] && [ "$over" = 0 ]; then echo "ERROR: Wazuh manager components are already installed. Use option -o|--overwrite"; exit 1; fi
echo 5.0.0-latest > "$FAKE/installed-wazuh-manager"; echo "INFO: Wazuh manager installation finished"
"""


class FailedMasterInstallCanRunAgainRpmB(_Node):
    """E6-cluster-rpm B: after a failed master install whose package went in, "fix the cause and run again" could not
    work: the 5.0 assistant refused "already installed ... -o". Chosen: run again with -o (not "back master only"). It is
    what the all-in-one does over a partial 5.0 (rule 2: -o over 5.0, never over 4.x); the step has no success of this
    bundle, the import and the opening come after it, so the partial 5.0 holds nothing to keep; and it leaves the person
    both ways out the message offers. A 4.x package still there is refused, never overwritten."""

    def setup(self, tree, installed):
        n = self.node(tree)
        fake = os.path.join(n.t, "fake")
        os.makedirs(fake)
        n.env["FAKE"] = fake
        if installed:
            write(os.path.join(fake, "installed-wazuh-manager"), installed + "\n")
        n.stub("rpm", 'if [ "$1" = -q ] && [ -e "%s/installed-${@: -1}" ]; then cat "%s/installed-${@: -1}"; else echo "package ${@: -1} is not installed"; exit 1; fi' % (fake, fake))
        write(os.path.join(n.env["MIG_HOME"], "v5", "wazuh-install.sh"), ASSISTANT5, 0o755)
        write(n.env["V5_TAR"], "5.0 install files (fake)\n")
        rc, out = n.run("install5.sh", "-wm", "wazuh-1")
        calls = open(os.path.join(fake, "assistant.calls")).read() if os.path.exists(os.path.join(fake, "assistant.calls")) else ""
        return rc, out, calls

    def test_a_partial_5x_manager_is_installed_again_with_o(self):
        rc, out, calls = self.setup(SRC, "5.0.0-latest")
        self.assertEqual(rc, 0, out)
        self.assertIn("without a recorded success of this step", out)
        self.assertIn(" -o", calls)

    def test_a_4x_manager_is_refused(self):
        rc, out, calls = self.setup(SRC, "4.14.11-1")
        self.assertNotEqual(rc, 0)
        self.assertIn("(4.x) is still installed on this node", out)
        self.assertEqual(calls, "")

    def test_a_clean_node_runs_without_o(self):
        rc, out, calls = self.setup(SRC, "")
        self.assertEqual(rc, 0, out)
        self.assertNotIn(" -o", calls)



if __name__ == "__main__":
    unittest.main()
