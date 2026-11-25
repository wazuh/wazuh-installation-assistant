"""The fold of the three E3 end-to-end runs (E3-deb, E3-rpm, E3-cluster) into src/: the runs' own fixes and the tool bugs they found."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock

import helpers
from test_e2_cluster import NodeSteps, tgz, write as cwrite

SRC = helpers.SRC
MIGRATE = os.path.join(SRC, 'migrate.sh')

H = helpers.load(os.path.join(SRC, "mig_helper.py"), "e3_mig_helper")
BS = helpers.load(os.path.join(SRC, "bundle_secrets.py"), "e3_bundle_secrets")

KEY = "0123456789abcdef0123456789abcdef01234567"
CLUSTER_KEY = "3123456789abcdef0123456789abcdef"


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


class _Node(unittest.TestCase):
    def node(self, tree=SRC):
        n = NodeSteps(tree)
        self.addCleanup(n.close)
        return n

    def cluster_bundle(self, n):
        """A cluster manager bundle whose rollback archive carries an agent key and the 4.x cluster key."""
        tgz(os.path.join(n.bundle, "v4", "rollback", "var-ossec.tar.gz"),
            {"var/ossec/etc/client.keys": ("002 ag1 any %s\n" % KEY).encode(),
             "var/ossec/etc/ossec.conf": ("<ossec_config><cluster><key>%s</key></cluster></ossec_config>" % CLUSTER_KEY).encode()})


# ------------------------------------------------------------------------------------------------ 1. cluster fix 01
class ClusterWayBackInstallFilesCluster01(_Node):
    """The way back's copy of the 4.x install files (every 4.x password, the cluster key) failed the finish's sweep."""

    def reinstall(self, tree):
        n = self.node(tree)
        cwrite(n.p("/home/ec2-user/v4/wazuh-install.sh"), "#!/bin/bash\necho 'INFO: --- Summary ---'\necho 'INFO: Password: s3cr3t-admin'\nexit 0\n", 0o755)
        tgz(n.env["V4_TAR"], {"wazuh-install-files/wazuh-passwords.txt": b"x"}, gz=False)
        rc, out = n.run("goback-install4.sh", "--wazuh-server", "wazuh-1")
        return n, rc, out, n.p("/root/mig-work/v4-reinstall/wazuh-install-files.tar")

    def test_the_way_back_removes_its_copy_after_the_assistant(self):
        n, rc, out, copy = self.reinstall(SRC)
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(copy), out)
        self.assertIn("its copy of the install files removed", out)


    def finish_secrets(self, tree):
        n = self.node(tree)
        self.cluster_bundle(n)
        copy = n.p("/root/mig-work/v4-reinstall/wazuh-install-files.tar")
        tgz(copy, {"wazuh-install-files/config.yml": ("cluster key: %s\n" % CLUSTER_KEY).encode()}, gz=False)
        rc, out = n.run("finish-node.sh", "secrets")
        return rc, out, copy

    def test_the_finish_removes_a_copy_an_earlier_way_back_left(self):
        rc, out, copy = self.finish_secrets(SRC)
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(copy))
        self.assertIn("removed the way back's working copy", out)



# ------------------------------------------------------------------------------------------------ 2. cluster fix 02
class ClusterFinishRunsTwiceCluster02(_Node):
    """legacy-decide exit 3 means a second finish; its history-data crashed on what the first finish's sweep deleted."""

    def second(self, tree):
        n = self.node(tree)
        os.makedirs(os.path.join(n.bundle, "history"))
        cwrite(os.path.join(n.node, "history5-master.sh"),
               "#!/bin/bash\necho 'FileNotFoundError: identity/manifest.json'; exit 1\n", 0o755)
        cwrite(os.path.join(n.bundle, "state", "finish.history_data"), "2026-11-24T17:44:00Z\n")
        return n.run("finish-node.sh", "history-data", "https://idx1:9200")

    def test_the_second_finish_skips_what_the_first_did(self):
        rc, out = self.second(SRC)
        self.assertEqual(rc, 0, out)
        self.assertIn("already removed after its proof", out)



# ------------------------------------------------------------------------------------------------ 3. cluster fix 03
class LoosePrivateKeyIsNamedCluster03(unittest.TestCase):
    """-g on indexer node-1 leaves the 5.0 CA key in the work directory; the sweep failed every cluster finish there."""
    PEM = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n"

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)
        self.b = os.path.join(self.t, "bundle")
        write(os.path.join(self.b, "v4", "etc", "client.keys"), "001 ag1 any %s\n" % KEY)
        os.makedirs(os.path.join(self.b, "state"))
        self.work = os.path.join(self.t, "work")
        write(os.path.join(self.work, "v5", "wazuh-ca", "root-ca.key"), self.PEM)

    def test_a_loose_key_is_named_not_a_failure(self):
        rc, out = quiet(BS.sweep, self.b, [self.work], (), False, [self.t])
        self.assertEqual(rc, 0, out)
        self.assertIn("wazuh-ca/root-ca.key (a private key, not a value this bundle carried", out)

    def test_a_carried_value_beside_the_key_still_fails(self):
        write(os.path.join(self.work, "v5", "wazuh-ca", "root-ca.key"), self.PEM + ("agent %s\n" % KEY).encode())
        rc, out = quiet(BS.sweep, self.b, [self.work], (), False, [self.t])
        self.assertEqual(rc, 1, out)
        self.assertIn("key of agent 001 in", out)

    def test_a_key_inside_the_bundle_still_fails(self):
        write(os.path.join(self.b, "logs", "leak.pem"), self.PEM)
        rc, out = quiet(BS.sweep, self.b, [self.work], (), False, [self.t])
        self.assertEqual(rc, 1, out)



# ------------------------------------------------------------------------------------------------ 4. cluster fix 04 = deb N7
def _ts(s):
    return time.mktime(time.strptime(s, "%Y/%m/%d %H:%M:%S"))


CU = "wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: "
VS = "wazuh-manager-modulesd:vulnerability-scanner: INFO: "
START = CU + "Consumer 'cti:catalog:consumer:vulnerabilities' in index '.wazuh-cti-consumers' is ready. Starting feed download."
# E3-deb 30-bundle-b/22 and E3-cluster 10-run/64c (lines as logged): the first load, then a restart after it
FIRST_LOAD = ["2026/11/24 18:16:55 " + VS + "The local feed database is incomplete at startup: required global maps are missing. Clearing updater state to force a clean rebuild.",
              "2026/11/24 18:16:55 " + VS + "CVE feed not yet available — per-agent scans deferred until initial load completes.",
              "2026/11/24 18:23:55 " + START,
              "2026/11/24 18:27:00 " + CU + "Slice 0 (1/2) in progress — 204800 documents so far, cursor '1324739', 424s elapsed",
              "2026/11/24 18:31:28 " + CU + "Initial load download phase complete — 424972 documents, cursor: '1346239'",
              "2026/11/24 18:31:29 " + VS + "Feed update process completed (changed=true).",
              "2026/11/24 18:31:29 " + VS + "CVE feed fully loaded — per-agent scans unblocked."]
RESTART = ["2026/11/24 19:19:07 " + VS + "Started (pid: 289262).",
           "2026/11/24 19:19:07 " + START,
           "2026/11/24 19:19:07 " + CU + "Starting incremental update from offset 1346239",
           "2026/11/24 19:19:07 " + CU + "Incremental update download phase complete — 0 documents, new cursor: '1346239'",
           "2026/11/24 19:19:07 " + VS + "Feed update process completed (changed=false)."]
# E3-cluster 10-run/64c: three restarts interrupted the first load, the fourth completed it
INTERRUPTED = ["2026/11/24 17:31:34 " + START,
               "2026/11/24 17:31:38 " + CU + "Initial load interrupted by stop request — cursor not persisted, 8400 documents processed this cycle will be re-fetched",
               "2026/11/24 17:31:38 " + CU + "Initial load download phase interrupted — 8400 documents, cursor: ''",
               "2026/11/24 17:31:44 " + VS + "The local feed database is incomplete at startup: required global maps are missing. Clearing updater state to force a clean rebuild.",
               "2026/11/24 17:31:44 " + START]


class FeedCompleteAfterARestartCluster04DebN7(unittest.TestCase):
    """A restart after a complete load logs an incremental update and 'Feed update process completed', never 'CVE feed
    fully loaded' again: the wait failed on a loaded feed (feed-wait NOT LOADED, cluster legacy-close, deb agents/finish
    reruns). A first load still running must never read as loaded."""

    def test_a_restart_after_a_complete_load_is_complete(self):
        self.assertEqual(H.feed_load_state(FIRST_LOAD + RESTART, _ts("2026/11/24 19:21:36")), ("complete", "2026/11/24 19:19:07"))


    def test_the_first_load_completes_on_either_line(self):
        self.assertEqual(H.feed_load_state(FIRST_LOAD, _ts("2026/11/24 18:40:00")), ("complete", "2026/11/24 18:31:29"))
        no_fully = [l for l in FIRST_LOAD if "fully loaded" not in l]
        self.assertEqual(H.feed_load_state(no_fully, _ts("2026/11/24 18:40:00")), ("complete", "2026/11/24 18:31:29"))

    def test_a_first_load_still_running_is_never_loaded(self):
        running = FIRST_LOAD[:4]
        self.assertEqual(H.feed_load_state(running, _ts("2026/11/24 18:28:00"))[0], "loading")
        self.assertEqual(H.feed_load_state(running, _ts("2026/11/24 19:00:00"))[0], "quiet")
        self.assertEqual(H.feed_load_state(INTERRUPTED, _ts("2026/11/24 17:32:00"))[0], "loading")

    def test_a_completion_line_inside_a_full_load_does_not_count(self):
        """Only a load that is incremental, or whose initial download completed, ends on 'Feed update process completed'.
        The run's own fix (a second alternative in the completion regex) would take this as loaded."""
        odd = INTERRUPTED + ["2026/11/24 17:31:50 " + VS + "Feed update process completed (changed=false)."]
        self.assertEqual(H.feed_load_state(odd, _ts("2026/11/24 17:32:00"))[0], "loading")
        self.assertEqual(H.feed_load_state(odd, _ts("2026/11/24 18:00:00"))[0], "quiet")

    def test_a_feed_removed_after_a_complete_load_loads_again(self):
        """E3-cluster 64d: the local feed removed, the manager started: a full load in progress after an earlier complete."""
        again = FIRST_LOAD + RESTART + [
            "2026/11/24 19:57:18 " + VS + "No existing local vulnerability feed detected at startup. A full feed will be downloaded.",
            "2026/11/24 19:57:18 " + START]
        self.assertEqual(H.feed_load_state(again, _ts("2026/11/24 19:58:00"))[0], "loading")

    def test_feed_wait_returns_on_the_restart_lines(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        log = write(os.path.join(t, "wazuh-manager.log"), "\n".join(FIRST_LOAD + RESTART) + "\n")
        clock = [_ts("2026/11/24 19:21:36")]
        r, out = quiet(H.feed_wait, log, "60", "", "30", lambda: clock[0], lambda s: clock.__setitem__(0, clock[0] + s))
        self.assertEqual(r, 0, out)
        self.assertIn("load is complete", out)
        clock = [_ts("2026/11/24 19:21:36")]


# ------------------------------------------------------------------------------------------------ 5. cluster fix 00
class InstallFilesHostToHostCluster00(unittest.TestCase):
    """k5.sh idx copied the 5.0 install files (every 5.0 password, the CA key) into a file on the controller."""


    def test_the_install_files_never_land_on_the_controller(self):
        # CL1: k5.sh idx calls the cluster command; its indexers phase streams the files host to host
        from test_cl1_cluster import Cluster
        c = Cluster()
        try:
            rc, out, calls = c.run("run", "--through", "indexers")
            self.assertEqual(rc, 0, out[-2000:])
            self.assertIn("10.0.0.1 cat /root/wazuh-migration/v5/wazuh-install-files.tar", calls)
            for r in ("10.0.0.2", "10.0.0.11", "10.0.0.12", "10.0.0.21"):
                self.assertTrue([x for x in calls if x.startswith(r + " sh -c") and "v5/wazuh-install-files.tar.part" in x], r)
            here = [os.path.join(d, f) for d, _, fs in os.walk(c.t) for f in fs if f != "fakessh" and "TAR-CONTENT" in open(os.path.join(d, f), errors="replace").read()]
            self.assertEqual(here, [])
        finally:
            c.close()




# ------------------------------------------------------------------------------------------------ 6. rpm fix 01
class SettingsBaseCollectionPowerCutRpm01(unittest.TestCase):
    """A hard reboot 0.2 s into replace.settings_plan left base-installed/ without targets.json; the rerun skipped the
    collection on wazuh-manager.conf alone, marked the step, and import.settings stopped on every rerun."""
    CONF = "<wazuh_config><remote/></wazuh_config>\n"

    def sh(self, script=MIGRATE):
        sh = helpers.Shell(script)
        self.addCleanup(sh.close)
        sh.write("etc/wazuh-manager/wazuh-manager.conf", self.CONF, base=sh.root)
        sh.write("etc/wazuh-manager/wazuh-manager-internal-options.conf", "x.y=1\n", base=sh.root)
        sh.write("var/wazuh-manager/api/configuration/api.yaml", "host: 0.0.0.0\n", base=sh.root)
        # what the cut left: the copies, but no targets.json (written after them)
        sh.write("settings/base-installed/wazuh-manager.conf", self.CONF)
        sh.write("settings/base-installed/api.yaml", "host: 0.0.0.0\n")
        self.fake = os.path.join(sh.tmp, "fake")
        write(os.path.join(self.fake, "settings_stage.py"), "import sys\nprint('CONVERT', sys.argv[1])\nsys.exit(7)\n")
        return sh

    def plan(self, sh):
        return sh.run('settings_plan() { echo "PLAN $1"; return 0; }; CARRY_SETTINGS=1; rp_settings_plan')

    def importing(self, sh):
        return sh.run('HERE=%s; CARRY_SETTINGS=1; im_settings' % self.fake)

    def test_the_rerun_completes_a_cut_collection(self):
        sh = self.sh()
        rc, out = self.plan(sh)
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.getsize(os.path.join(sh.bundle, "settings", "targets.json")) > 0, out)
        self.assertTrue(os.path.exists(os.path.join(sh.bundle, "settings", "base-installed", "wazuh-manager-internal-options.conf")))
        self.assertFalse(os.path.exists(os.path.join(sh.bundle, "settings", "base-installed.partial")))

    def test_a_cut_collection_leaves_the_previous_base_or_nothing(self):
        """The collection is gathered beside the base and renamed: a .partial left by a cut is never read as the base."""
        sh = self.sh()
        shutil.rmtree(os.path.join(sh.bundle, "settings", "base-installed"))
        sh.write("settings/base-installed.partial/wazuh-manager.conf", self.CONF)
        rc, out = self.plan(sh)
        self.assertEqual(rc, 0, out)
        self.assertEqual(sorted(os.listdir(os.path.join(sh.bundle, "settings", "base-installed"))),
                         ["api.yaml", "wazuh-manager-internal-options.conf", "wazuh-manager.conf"])


    def test_a_bundle_cut_before_the_fix_is_completed_at_the_import_while_nothing_is_staged(self):
        sh = self.sh()
        rc, out = self.importing(sh)
        self.assertEqual(rc, 1, out)                       # the fake converter's exit, after the completion
        self.assertIn("collected again, nothing was staged yet", out)
        self.assertIn("CONVERT convert", out)
        self.assertTrue(os.path.exists(os.path.join(sh.bundle, "settings", "targets.json")))

    def test_once_something_is_staged_the_import_stops(self):
        sh = self.sh()
        os.makedirs(os.path.join(sh.bundle, "settings", "saved"))
        rc, out = self.importing(sh)
        self.assertEqual(rc, 1, out)
        self.assertIn("the installed base was not collected", out)
        self.assertNotIn("CONVERT", out)
        sh2 = self.sh()
        sh2.write("etc/wazuh-manager/wazuh-manager.conf", "<wazuh_config>staged</wazuh_config>\n", base=sh2.root)
        rc, out = self.importing(sh2)
        self.assertNotIn("CONVERT", out)


# ------------------------------------------------------------------------------------------------ 7. deb N6
import test_of1  # noqa: E402  (its one-file history bundle and fake indexer)

HL = helpers.load(os.path.join(SRC, "history_load.py"), "e3_history_load", extra_path=SRC)


def restarting_indexer(down_breaker, down_bulk):
    """test_of1's fake indexer, refusing the connection to the first down_breaker breaker reads and down_bulk bulks."""
    base = test_of1.FakeIndexer

    class Restarting(base):
        def __call__(self, method, path, body=None, timeout=600):
            kind = "breaker" if path.startswith("/_nodes/stats") else "bulk" if "/_bulk" in path else None
            left = {"breaker": down_breaker, "bulk": down_bulk}
            n = sum(1 for e in self.log if e[0] == "refused-" + str(kind))
            if kind and n < left[kind]:
                self.log.append(("refused-" + kind, self.clock.t))
                raise ConnectionRefusedError(111, "Connection refused")
            return base.__call__(self, method, path, body, timeout)
    return Restarting


class LoaderWaitsForARestartingIndexerDebN6(test_of1._LoaderBundle):
    """An indexer restart during the history load: the guard's breaker read raised ConnectionRefusedError and the load
    ended with a traceback (E3-deb 30-bundle-b/11). It is 'indexer not ready': wait and retry, same stop time."""

    def run_load(self, mod, down_breaker, down_bulk, wait_max=1800):
        fake_cls = restarting_indexer(down_breaker, down_bulk)
        with mock.patch("test_of1.FakeIndexer", fake_cls):
            try:
                return self.load(mod, [0.10], [], breaker_max=0.85, breaker_wait_max=wait_max)
            except ConnectionRefusedError as e:
                return e, None, None, ""

    def test_a_refused_breaker_read_waits_then_goes_on(self):
        stats, fake, clock, out = self.run_load(HL, 3, 0)
        self.assertNotIsInstance(stats, Exception, out)
        self.assertEqual(len(fake.created), 5)
        self.assertIn("indexer not ready (ConnectionRefusedError", out)
        self.assertEqual(stats["not_ready_s"], 2.0 + 4.0 + 8.0)

    def test_a_refused_bulk_is_sent_again(self):
        stats, fake, clock, out = self.run_load(HL, 0, 2)
        self.assertNotIsInstance(stats, Exception, out)
        self.assertEqual(len(fake.created), 5)
        self.assertEqual(len([e for e in fake.log if e[0] == "refused-bulk"]), 2)

    def test_an_indexer_that_never_comes_back_stops_the_load_resumable(self):
        stats, fake, clock, out = self.run_load(HL, 10 ** 6, 0, wait_max=120)
        self.assertIsInstance(stats, RuntimeError, out)
        self.assertIn("did not answer for 120 s", str(stats))
        self.assertIn("resumes with the same command", str(stats))
        self.assertFalse(fake.created)



# ------------------------------------------------------------------------------------------------ 8. deb N4
class FakeISM:
    """The 4.x indexer's ISM API as mig_helper.idx sees it: policies by id, the policy attached to each alert index."""

    def __init__(self, policies, attached, indices):
        self.pol, self.att, self.indices, self.calls = dict(policies), dict(attached), set(indices), []

    def __call__(self, method, path, password, body=None, **k):
        self.calls.append((method, path.split("?")[0]))
        p = path.split("?")[0]
        if p == "/_plugins/_ism/policies":
            if not self.pol:
                return 404, {"error": "no such index [.opendistro-ism-config]"}
            return 200, {"policies": [{"_id": i, "_seq_no": 3, "_primary_term": 1,
                                       "policy": dict(b, policy_id=i, last_updated_time=1, schema_version=21)} for i, b in self.pol.items()]}
        if p.startswith("/_plugins/_ism/policies/"):
            pid = urllib_unquote(p.rsplit("/", 1)[1])
            if method == "GET":
                return (200, {"_id": pid}) if pid in self.pol else (404, {})
            assert set(body) == {"policy"} and "policy_id" not in body["policy"] and "last_updated_time" not in body["policy"], body
            self.pol[pid] = body["policy"]
            return 201, {"_id": pid}
        if p.startswith("/_plugins/_ism/explain/"):
            r = {i: {"index.plugins.index_state_management.policy_id": self.att.get(i)} for i in sorted(self.indices)}
            r["total_managed_indices"] = len(self.att)
            return 200, r
        if p.startswith("/_plugins/_ism/add/"):
            got = p.rsplit("/", 1)[1].split(",")
            for i in got:
                self.att[i] = body["policy_id"]
            return 200, {"updated_indices": len(got), "failures": False, "failed_indices": []}
        return 404, {}


def urllib_unquote(x):
    import urllib.parse
    return urllib.parse.unquote(x)


DAYS = ["wazuh-alerts-4.x-2026.07.%02d" % d for d in range(1, 4)] + ["wazuh-alerts-4.x-2026.08.25", "wazuh-alerts-4.x-2026.10.30"]
DELETE_90 = {"default_state": "hot", "states": test_of1.HOT_DELETE("90d"), "ism_template": [{"index_patterns": ["wazuh-alerts-*"], "last_updated_time": 5}]}
HOLD_60 = {"default_state": "hot", "states": test_of1.HOT_DELETE("60d")}


class GoingBackRestoresTheISMPoliciesDebN4(unittest.TestCase):
    """Going back lost the 4.x ISM policies: the site kept no retention and bundle C read "none" and loaded 365 days
    (E3-deb 20-bundle-c/bundle/retention-4x.json). Chosen: put them back on `back` (see MERGE-LOG)."""

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)
        # the source: the template policy on the newest days, the hand policy on one day, none on the oldest
        self.src = FakeISM({"wazuh-alert-retention-policy": DELETE_90, "acme-short-hold": HOLD_60},
                           {DAYS[3]: "acme-short-hold", DAYS[4]: "wazuh-alert-retention-policy"}, DAYS)

    def precopy(self, mod, fake, name):
        out = os.path.join(self.t, name, "retention-4x.json")
        with mock.patch.dict(os.environ, {"V4_INDEXER_ADMIN_PASSWORD": "x"}), mock.patch.object(mod, "idx", fake):
            rc, text = quiet(mod.retention_4x, out)
        self.assertEqual(rc, 0, text)
        return out, json.load(open(out))

    def test_the_precopy_records_bodies_and_attachments(self):
        out, r = self.precopy(H, self.src, "a")
        rec = json.load(open(os.path.join(os.path.dirname(out), "ism-4x.json")))
        self.assertEqual([p["policy_id"] for p in rec["policies"]], ["acme-short-hold", "wazuh-alert-retention-policy"])
        body = rec["policies"][1]["policy"]
        self.assertNotIn("last_updated_time", body)
        self.assertNotIn("policy_id", body)
        self.assertEqual(body["ism_template"], [{"index_patterns": ["wazuh-alerts-*"]}])
        self.assertEqual(rec["attached"], {DAYS[3]: "acme-short-hold", DAYS[4]: "wazuh-alert-retention-policy"})

    def back_then_next_bundle(self, mod):
        a, ra = self.precopy(mod, self.src, "a")
        self.assertEqual(ra["retention_days"], 90)
        back = FakeISM({}, {}, DAYS)                      # reinstalled 4.x: no policy, the alerts reloaded as new indices
        if hasattr(mod, "ism_restore4"):
            with mock.patch.dict(os.environ, {"V4_INDEXER_ADMIN_PASSWORD": "x"}), mock.patch.object(mod, "idx", back):
                rc, text = quiet(mod.ism_restore4, os.path.join(os.path.dirname(a), "ism-4x.json"))
            self.assertEqual(rc, 0, text)
        return back, self.precopy(mod, back, "c")[1]

    def test_going_back_puts_them_back_and_the_next_bundle_reads_90_days(self):
        back, rc_ = self.back_then_next_bundle(H)
        self.assertEqual(back.att, self.src.att)          # exactly the indices that had a policy, none more
        self.assertEqual(sorted(back.pol), sorted(self.src.pol))
        self.assertEqual(rc_["retention_days"], 90)


    def test_a_policy_already_there_is_kept_and_another_attachment_left(self):
        back = FakeISM({"acme-short-hold": {"default_state": "x", "states": []}}, {DAYS[4]: "site-new"}, DAYS)
        a, _ = self.precopy(H, self.src, "a")
        with mock.patch.dict(os.environ, {"V4_INDEXER_ADMIN_PASSWORD": "x"}), mock.patch.object(H, "idx", back):
            rc, text = quiet(H.ism_restore4, os.path.join(os.path.dirname(a), "ism-4x.json"))
        self.assertEqual(rc, 0, text)
        self.assertEqual(back.pol["acme-short-hold"], {"default_state": "x", "states": []})
        self.assertEqual(back.att[DAYS[4]], "site-new")
        self.assertIn("now under another policy", text)

    def test_a_refused_put_fails_the_step(self):
        a, _ = self.precopy(H, self.src, "a")
        back = FakeISM({}, {}, DAYS)
        refuse = lambda m, p, pw, body=None, **k: (403, {"error": "forbidden"}) if m == "PUT" else back(m, p, pw, body)
        with mock.patch.dict(os.environ, {"V4_INDEXER_ADMIN_PASSWORD": "x"}), mock.patch.object(H, "idx", refuse):
            rc, text = quiet(H.ism_restore4, os.path.join(os.path.dirname(a), "ism-4x.json"))
        self.assertEqual(rc, 1, text)

    def test_a_bundle_without_the_record_goes_back_and_says_so(self):
        with mock.patch.dict(os.environ, {"V4_INDEXER_ADMIN_PASSWORD": "x"}):
            rc, text = quiet(H.ism_restore4, os.path.join(self.t, "none", "ism-4x.json"))
        self.assertEqual(rc, 0, text)
        self.assertIn("create them again by hand", text)

    def test_the_step_runs_after_the_agents_and_before_the_secrets(self):
        t = open(MIGRATE).read()
        self.assertLess(t.index("step back.verify "), t.index("step back.retention "))
        self.assertLess(t.index("step back.retention "), t.index("step back.secrets "))
        self.assertIn("ism-4x.json", BS.PARTS)            # error_notification may hold a webhook: deleted with the parts


# ------------------------------------------------------------------------------------------------ 9. deb N3
class RunResumesTheHistoryPastPhase8DebN3(unittest.TestCase):
    """`run` re-ran phase 8 before the history; phase 8 failed while agent 003 reconnected after its stop (E3-deb
    30-bundle-b/09) and the history never started. Strict until it passed and the point of no return is confirmed."""

    def verify(self, script, confirmed=True, passed=True):
        sh = helpers.Shell(script)
        self.addCleanup(sh.close)
        if passed:
            sh.write("state/phase.verify", "2026-11-24T18:17:10Z\n")
        if confirmed:
            sh.write("state/confirm.no_return", "2026-11-24T18:17:26Z\n")
        # the compare as it ran at 18:33Z: agent 003 disconnected
        return sh, sh.run('host_state() { echo v5; }; vf_compare() { echo "agents active on 5.0  LOST  {\'003\': \'disconnected\'}"; '
                          'echo "report -> ${VERIFY_REPORT:-$BUNDLE_DIR/REPORT-verify.txt}"; return 1; }; '
                          'phase_verify; echo "rc=$? report_only=${VERIFY_REPORT_ONLY:-0}"')

    def test_after_the_confirmation_a_rerun_reports_and_the_history_goes_on(self):
        sh, (rc, out) = self.verify(MIGRATE)
        self.assertIn("rc=0 report_only=1", out)
        self.assertIn("WARNING phase 8 rerun: exit 1", out)
        self.assertIn("REPORT-verify-rerun.txt", out)
        self.assertEqual(open(os.path.join(sh.bundle, "state", "phase.verify")).read(), "2026-11-24T18:17:10Z\n")

    def test_before_the_confirmation_phase_8_stays_strict(self):
        sh, (rc, out) = self.verify(MIGRATE, confirmed=False)
        self.assertNotEqual(rc, 0, out)                 # the step runs the real compare in its own process and fails
        self.assertIn("FAIL  compare 5.0 with the fingerprint", out)
        self.assertNotIn("report_only=1", out)

    def test_the_first_time_phase_8_is_strict(self):
        sh, (rc, out) = self.verify(MIGRATE, confirmed=True, passed=False)
        self.assertNotEqual(rc, 0, out)
        self.assertNotIn("report_only=1", out)


    def test_the_loop_keeps_the_pass_mark(self):
        t = open(MIGRATE).read()
        self.assertIn('if [ "$CUR" = verify ] && [ "${VERIFY_REPORT_ONLY:-0}" = 1 ]; then', t)


# ------------------------------------------------------------------------------------------------ 10. deb N5
FU = helpers.load(os.path.join(SRC, "fleet-upgrade.py"), "e3_fleet_upgrade")


class PendingAgentAfterTheOpeningDebN5(unittest.TestCase):
    """`agents` 46 s after the opening skipped the Windows agent as 'pending' (re-applying the new shared configuration)
    with "re-run when it is back" (E3-deb 30-bundle-b/05). Wait for it, else name it."""
    SANS = ["198.51.100.13", "localhost", "wazuh-1"]

    def preflight(self, mod, statuses, pending_wait=None, ka_age=0):
        node = {"type": "master", "ip": "198.51.100.13", "poll_interval": 900, "task_manager": {},
                "remote": {"legacy": {"enabled": True}, "https": {"bind_addr": "0.0.0.0", "port": 1517, "verification_mode": "none"}},
                "tls": {"available": True, "listener": {"sans": self.SANS, "seconds_until_expiry": 10 ** 9},
                        "ca_bundle": {"chain_valid": True, "matches_active_leaf": True}}}
        mf = {"version": "v5.0.0", "nodes": {"wazuh-1": node}}
        ka = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - ka_age))
        reads = []

        def fleet(api, *x):
            st = statuses[min(len(reads), len(statuses) - 1)]
            reads.append(st)
            return [{"id": "004", "name": "e3deb-win", "version": "Wazuh v4.14.10", "status": st, "lastKeepAlive": ka,
                     "os": {"platform": "windows", "arch": "x86_64", "major": "10", "name": "Windows Server 2022", "version": "10.0"}}]
        facts = {"004": {"dialed": ["198.51.100.13"]}}
        a = types.SimpleNamespace(target="v5.0.0", poll_interval=None, wpk_repo="repo", step_wpk_repo=None, agents=None, groups=None,
                                  package_type=None, step_version=None, include_stale=False, include_disconnected=False,
                                  allow_cert_mismatch=False, listener_host="h", api="https://localhost:55000", canary_key="platform",
                                  batch_size=50, macos_anchor_placed=False, node_address=None, pending_wait=pending_wait)
        clock = [0.0]
        with mock.patch.object(mod, "manager_facts", lambda api: mf), mock.patch.object(mod, "fleet", fleet), \
                mock.patch.object(mod, "repo_has", lambda *x, **k: (True, "")), mock.patch.object(mod, "probe_listener", lambda *x: (True, "ok", "TLSv1.3")), \
                mock.patch.object(mod, "socket", types.SimpleNamespace(getaddrinfo=lambda *x: [], create_connection=None)), \
                mock.patch.object(mod.time, "sleep", lambda s_: clock.__setitem__(0, clock[0] + s_)), \
                mock.patch.object(mod.time, "monotonic", lambda: clock[0]):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                plan = mod.preflight(None, a, facts)["plan"]["004"]
        return plan["skip"], reads, clock[0], buf.getvalue()

    def test_a_pending_agent_is_waited_for_and_planned(self):
        skip, reads, t, out = self.preflight(FU, ["pending", "pending", "active"])
        self.assertIsNone(skip, out)
        self.assertEqual(reads, ["pending", "pending", "active"])
        self.assertEqual(t, 20)

    def test_still_pending_after_the_wait_it_is_named_as_pending(self):
        skip, reads, t, out = self.preflight(FU, ["pending"], pending_wait=60)
        self.assertIn("agent is pending after 60s of waiting", skip)
        self.assertIn("run the agents phase again once it is active", skip)

    def test_a_disconnected_agent_is_not_waited_for(self):
        # CL1 (E4-deb N-F5): one with a recent keepalive is waited for now (test_cl1_cluster); an hour-old one is not
        skip, reads, t, out = self.preflight(FU, ["disconnected", "active"], ka_age=3600)
        self.assertEqual(len(reads), 1)
        self.assertIn("agent is disconnected", skip)


    def test_the_gate_names_the_agents_to_run_again(self):
        sh = helpers.Shell(MIGRATE)
        self.addCleanup(sh.close)
        sh.write("fleet/upgrade-state.json", {"agents": {
            "002": {"name": "e3deb-ubuntu", "state": "upgraded"},
            "001": {"name": "e2deb-never", "state": "skipped", "reason": "no version on record (the agent never reported to this manager)"},
            "004": {"name": "e3deb-win", "state": "skipped", "reason": "agent is pending after 120s of waiting (connected ...)"}}})
        sh.write("fleet/trust-audit.txt", "002 e3deb-ubuntu v5.0.0 x verification_mode=full\n")
        rc, out = sh.run("ag_gate")
        self.assertEqual(rc, 0, out)
        self.assertIn("not active at the preflight, still on 4.x: 004: run 'migrate.sh agents' again", out)


# ------------------------------------------------------------------------------------------------ 11. secrets sweep
class SecretsSweepAfterTheFirstDebN2Rpm7Cluster3(unittest.TestCase):
    """deb N2 / rpm 7: cleaned bundles named "with its own secrets"; cluster 3: a rerun searched for nothing; rpm 7: the
    way back and discard left the bundle's 1.7 GB v4/offline set, which every later sweep read."""
    ENROLL = "short-pass"                                  # 10 characters: below the digest minimum

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)
        self.b = os.path.join(self.t, "bundle-b")
        write(os.path.join(self.b, "v4", "etc", "client.keys"), "001 ag1 any %s\n" % KEY)
        write(os.path.join(self.b, "v4", "etc", "authd.pass"), self.ENROLL + "\n")
        write(os.path.join(self.b, "v4", "etc", "ossec.conf"), "<ossec_config><cluster><key>%s</key></cluster></ossec_config>" % CLUSTER_KEY)
        write(os.path.join(self.b, "state", "phase.verify"), "x\n")
        self.work = os.path.join(self.t, "work")
        os.makedirs(self.work)

    def other(self, name, cleaned):
        d = os.path.join(self.t, name)
        write(os.path.join(d, "journal.ndjson"), "{}\n")
        write(os.path.join(d, "state", "back.done"), "x\n")
        write(os.path.join(d, "logs", "back.log"), "kept\n")
        if not cleaned:
            write(os.path.join(d, "v4", "etc", "client.keys"), "002 ag2 any %s\n" % ("f" * 40))
        return os.path.realpath(d)

    def sweep(self, mod):
        return quiet(mod.sweep, self.b, [self.work], (), False, [self.t])

    def test_cleaned_bundles_are_not_named_as_holding_secrets(self):
        a, c = self.other("bundle-a", cleaned=True), self.other("bundle-c", cleaned=False)
        rc, out = self.sweep(BS)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("%s (another migration bundle" % a, out)
        self.assertIn("their secrets already deleted (discarded, gone back or finished): %s" % a, out)
        self.assertIn("%s (another migration bundle on this host: an earlier or abandoned run, with its own secrets" % c, out)


    def test_a_rerun_still_searches_for_the_values(self):
        rc, out = self.sweep(BS)
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(os.path.join(self.b, "v4", "etc")))
        rec = open(os.path.join(self.b, "state", "secret-digests.json")).read()
        for v in (KEY, CLUSTER_KEY, self.ENROLL):
            self.assertNotIn(v, rec)                       # digests only
        write(os.path.join(self.work, "copy", "notes.txt"), "found later: key=%s;\n" % KEY)
        tgz(os.path.join(self.b, "logs", "x.tar.gz"), {"conf.xml": ("<key>%s</key>" % CLUSTER_KEY).encode()})
        rc, out = self.sweep(BS)
        self.assertEqual(rc, 1, out)
        self.assertIn("secret values this bundle carried: 2 (4.x cluster key, key)", out)
        self.assertIn("2 of them searched by the digest an earlier sweep recorded", out)
        self.assertIn("key of agent 001 in %s" % os.path.join(self.work, "copy", "notes.txt"), out)
        self.assertIn("4.x cluster key in %s:conf.xml" % os.path.join(self.b, "logs", "x.tar.gz"), out)
        self.assertIn("not searched again: enrollment password (shorter than 16 characters", out)

    def test_a_clean_rerun_passes(self):
        self.assertEqual(self.sweep(BS)[0], 0)
        rc, out = self.sweep(BS)
        self.assertEqual(rc, 0, out)
        self.assertIn("secret values this bundle carried: 2", out)


    def offline(self, script):
        sh = helpers.Shell(script)
        self.addCleanup(sh.close)
        sh.write("v4/offline/wazuh-offline.tar.gz", "pkg" * 100)
        sh.write("v4/etc/client.keys", "001 ag1 any %s\n" % KEY)
        rc, out = sh.run("abandoned_secrets", env={"MIG_BUNDLE_ROOTS": sh.tmp})
        return os.path.exists(os.path.join(sh.bundle, "v4", "offline")), rc, out

    def test_back_and_discard_remove_the_offline_package_set(self):
        left, rc, out = self.offline(MIGRATE)
        self.assertEqual(rc, 0, out)
        self.assertFalse(left, out)
        self.assertIn("v4/offline (the 4.x package set kept for an offline way back", out)


    def test_the_cluster_finish_twice(self):
        """E3-cluster 63-secrets-*.log: the second finish said 'carried: 0'."""
        n = NodeSteps(SRC)
        self.addCleanup(n.close)
        tgz(os.path.join(n.bundle, "v4", "rollback", "var-ossec.tar.gz"), {"var/ossec/etc/client.keys": ("002 ag1 any %s\n" % KEY).encode()})
        self.assertEqual(n.run("finish-node.sh", "secrets")[0], 0)
        rc, out = n.run("finish-node.sh", "secrets")
        self.assertEqual(rc, 0, out)
        self.assertIn("secret values this bundle carried: 1 (key)", out)


# ------------------------------------------------------------------------------------------------ 12. deb N1
IS = helpers.load(os.path.join(SRC, "identity_stage.py"), "e3_identity_stage")
EQUAL = {k: [] for k in ("groups_missing", "conf_differs", "policies_missing", "agents_missing", "membership_differs",
                         "renamed", "keys_differ", "agents_extra")}


class IdentityStageRestartsOnlyAfterAWriteDebN1(unittest.TestCase):
    """The hand repair changed nothing and still restarted the manager ("apply nothing", 7.9 s), dropping every agent
    (E3-deb 10-bundle-a/09); on the cluster master three identity-stage restarts each threw away the feed's first load."""

    def run_stage(self, mod, writes=(), pending=None):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        json.dump({"agents": [{"id": 1, "name": "ag1", "key": "K1", "groups": ["default"]}], "groups": []},
                  open(os.path.join(d, "manifest.json"), "w"))
        stdir = os.path.join(d, "st")
        if pending:
            os.makedirs(stdir)
            json.dump({"runs": [], "steps": {}, "restart_pending": pending}, open(os.path.join(stdir, "state.json"), "w"))
        args = types.SimpleNamespace(state=stdir, bundle=d, limit_mode="stock", raised_value=0, workers=1, chunk=500,
                                     max_passes=1, cooldown_wait=0, stop_after=None, with_password=False, with_rbac=False,
                                     expected_conf=None)
        ran = []

        def fake_groups(api, st, *a, **k):
            for w in writes:
                if hasattr(mod, "will_write"):
                    mod.will_write(st, w)
            return 0, 0

        def up(*a, **k):
            import urllib.error
            raise urllib.error.HTTPError("https://localhost:55000/", 401, "unauthorized", {}, None)
        patches = [mock.patch.object(mod, "read_api_yaml_limit", lambda: (300, None)),
                   mock.patch.object(mod, "Api", lambda *a, **k: types.SimpleNamespace(stats={}, set_budget=lambda v: None)),
                   mock.patch.object(mod, "preflight", lambda *a, **k: {"blockers": [], "conf_refused": []}),
                   mock.patch.object(mod, "read_registry", lambda api: ({"001": {"name": "ag1", "groups": ["default"]}}, {"default"})),
                   mock.patch.object(mod, "registry_keys", lambda path=None: {"001": ("ag1", "K1")}),
                   mock.patch.object(mod, "do_groups", fake_groups),
                   mock.patch.object(mod, "do_inserts", lambda *a, **k: 0),
                   mock.patch.object(mod, "do_memberships", lambda *a, **k: 0),
                   mock.patch.object(mod, "compare", lambda *a, **k: (dict(EQUAL), {}, set())),
                   mock.patch.object(mod, "restart_cmd", lambda: ["systemctl", "restart", "wazuh-manager"]),
                   mock.patch.object(mod.subprocess, "run", lambda cmd, **k: ran.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", "")),
                   mock.patch.object(mod.urllib.request, "urlopen", up)]
        with contextlib.ExitStack() as es:
            for x in patches:
                es.enter_context(x)
            r, out = quiet(mod.cmd_run, args)
        state = json.load(open(os.path.join(stdir, "state.json")))
        return r, out, [c for c in ran if "restart" in c], state

    def test_a_run_that_wrote_nothing_does_not_restart(self):
        r, out, restarts, st = self.run_stage(IS)
        self.assertEqual(r, 0, out)
        self.assertEqual(restarts, [], out)
        self.assertIn("manager restart skipped", out)
        self.assertIn("GATE PASS", out)


    def test_a_write_still_gets_its_restart(self):
        r, out, restarts, st = self.run_stage(IS, writes=["agent.conf of acme-audit"])
        self.assertEqual(len(restarts), 1, out)
        self.assertIn("apply agent.conf of acme-audit", out)
        self.assertNotIn("restart_pending", st)

    def test_a_killed_runs_writes_are_restarted_for_by_the_rerun(self):
        r, out, restarts, st = self.run_stage(IS, pending="agent 002")
        self.assertEqual(len(restarts), 1, out)
        self.assertNotIn("restart_pending", st)


# ------------------------------------------------------------------------------------------------ 13. cluster gaps 1 and 6
class MixedVersionClusterIsRefusedByNameClusterGaps1And6(_Node):
    """A 4.14.9 worker could not join the 4.14.10 master (Error 3031), so /cluster/nodes listed only wazuh-1 and the
    master's check passed (E3-cluster 02-o12/03, 05); the per-node refusal named ip-198-51-100-10, not wazuh-2."""
    NODES = [{"name": "wazuh-1", "type": "master", "version": "4.14.10", "ip": "198.51.100.11"}]

    def cluster(self, mod, agents=(), env=None, *expect):
        class FakeApi:
            def __init__(self, pw):
                pass

            def get(self, path):
                return list(MixedVersionClusterIsRefusedByNameClusterGaps1And6.NODES) if path.startswith("/cluster/nodes") else list(agents)
        with mock.patch.object(mod, "Api", FakeApi), mock.patch.dict(os.environ, dict({"V4_API_PASSWORD": "x"}, **(env or {}))):
            if "CLUSTER_NODES" not in (env or {}):
                os.environ.pop("CLUSTER_NODES", None)
            return quiet(mod.source_version_cluster, *expect)

    def test_a_worker_in_the_inventory_that_is_not_connected_is_refused_by_name(self):
        rc, out = self.cluster(H, env={"CLUSTER_NODES": "wazuh-1,wazuh-2"})
        self.assertEqual(rc, 1, out)
        self.assertIn("SOURCE VERSION REFUSED: manager node wazuh-2 is not connected to the master", out)
        self.assertIn("named in the inventory (CLUSTER_NODES)", out)

    def test_a_worker_the_registry_names_is_refused_without_an_inventory(self):
        rc, out = self.cluster(H, agents=[{"id": "000", "node_name": "wazuh-1"}, {"id": "003", "node_name": "wazuh-2"},
                                          {"id": "004", "node_name": "wazuh-2"}])
        self.assertEqual(rc, 1, out)
        self.assertIn("the agent registry (2 agent(s) last served by it)", out)

    def test_every_node_connected_passes(self):
        rc, out = self.cluster(H, env={"CLUSTER_NODES": "wazuh-1"}, agents=[{"id": "002", "node_name": "wazuh-1"}])
        self.assertEqual(rc, 0, out)


    def node_refusal(self, tree):
        n = self.node(tree)
        cwrite(n.p("/var/ossec/etc/ossec.conf"), "<ossec_config><cluster>\n  <name>wazuh</name>\n  <node_name>wazuh-2</node_name>\n</cluster></ossec_config>\n")
        n.stub("rpm", 'case "$*" in *wazuh-manager*) echo 4.14.9-1;; *) echo "package not installed";; esac')
        n.stub("hostname", 'case "$1" in -s) echo ip-198-51-100-10;; *) echo 10.0.0.2;; esac')
        return n.run("source-version.sh")

    def test_the_refusal_names_the_cluster_node(self):
        rc, out = self.node_refusal(SRC)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("wazuh-manager 4.14.9-1 on wazuh-2 (ip-198-51-100-10) is older than 4.14.10", out)


    def test_the_controller_passes_its_inventory(self):
        mc = open(os.path.join(SRC, "migrate-cluster.sh")).read()    # CL1: the cluster command, from its inventory
        self.assertIn("CLUSTER_NODES=%q", mc)
        self.assertIn('nstep "$MASTER" source-version.sh cluster', mc)


# ------------------------------------------------------------------------------------------------ 14. cluster gap 5
class SecondForwardAttemptChecksTheSourceClusterGap5(_Node):
    """The freeze ran its source-version gate only without T_manager4_stop_begin, so a second forward attempt after a
    way back (a 4.x reinstall, possibly of another build) was never checked (E3-cluster SCORECARD gap 6 [S])."""

    def second_freeze(self, tree):
        n = self.node(tree)
        cwrite(os.path.join(n.bundle, "state", "T_manager4_stop_begin"), "2026-11-24T17:15:48Z\n")    # the first attempt
        cwrite(n.p("/var/ossec/etc/ossec.conf"), "<ossec_config><cluster><node_name>wazuh-1</node_name><node_type>master</node_type></cluster></ossec_config>")
        cwrite(n.p("/var/ossec/logs/alerts/alerts.json"), "{}\n")
        n.stub("rpm", 'case "$*" in *wazuh-manager*) echo 4.14.9-1;; *) echo "package not installed";; esac')
        rc, out = n.run("freeze-manager.sh", env={"NO_DRAIN": "1"})
        return rc, out, n.called()

    def test_the_second_attempt_is_checked_too(self):
        rc, out, calls = self.second_freeze(SRC)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("SOURCE VERSION REFUSED: wazuh-manager 4.14.9-1 on wazuh-1", out)
        self.assertNotIn("systemctl stop wazuh-manager", calls)



# ------------------------------------------------------------------------------------------------ 15. cluster gap 2
class FilebeatRepairChecksSizeClusterGap2(_Node):
    """A reboot during the 4.x reinstall left filebeat.yml at 0 bytes and 10 zero-byte module files; the repair tested
    presence only and would have started Filebeat on them (E3-cluster 10-run/24b, DECISIONS)."""

    def cut_reinstall(self, tree):
        n = self.node(tree)
        r = os.path.join(n.bundle, "v4", "rollback")
        tgz(os.path.join(r, "etc-filebeat.tar.gz"), {"etc/filebeat/filebeat.yml": b"output.elasticsearch:\n  hosts: [x]\n"})
        tgz(os.path.join(r, "filebeat-module-wazuh.tar.gz"), {"usr/share/filebeat/module/wazuh/module.yml": b"M",
                                                              "usr/share/filebeat/module/wazuh/alerts/manifest.yml": b"A"})
        cwrite(n.p("/var/lib/filebeat/filebeat.keystore"), b"KS")
        cwrite(n.p("/etc/filebeat/filebeat.yml"), "")                       # what the cut left
        for f in ("module.yml", "alerts/manifest.yml"):
            cwrite(n.p("/usr/share/filebeat/module/wazuh/" + f), "")
        n.stub("rpm", "exit 0")
        n.stub("filebeat", 'echo "talk to server... OK"')
        n.stub("systemctl", '[ "$1" = is-active ] && { [ "$2" = -q ] && exit 0; echo active; }; exit 0')
        rc, out = n.run("filebeat-repair.sh")
        return n, rc, out

    def test_empty_files_are_put_back_from_the_bundle(self):
        n, rc, out = self.cut_reinstall(SRC)
        self.assertEqual(rc, 0, out)
        self.assertGreater(os.path.getsize(n.p("/etc/filebeat/filebeat.yml")), 0)
        self.assertEqual(open(n.p("/usr/share/filebeat/module/wazuh/module.yml"), "rb").read(), b"M")
        self.assertIn("Filebeat configuration was not this node's", out)   # CL1: compared with the bundle's archive
        self.assertIn("Filebeat wazuh module is damaged", out)


    def test_no_copy_in_the_bundle_stops_and_names_it(self):
        n = self.node()
        cwrite(n.p("/var/lib/filebeat/filebeat.keystore"), b"KS")
        cwrite(n.p("/etc/filebeat/filebeat.yml"), "")
        n.stub("rpm", "exit 0")
        rc, out = n.run("filebeat-repair.sh")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("rerun the 4.x assistant's Filebeat step", out)


# ------------------------------------------------------------------------------------------------ 16. rpm 4
class ManagerUpSaysTheApiIsSilentRpm4(unittest.TestCase):
    """After one hard reboot every 5.0 daemon ran but the API never listened; manager5_up waited about 3 min, then said
    "its daemons are not running (an unclean stop)" with an empty list (E3-rpm runA/32)."""

    def up(self, script):
        sh = helpers.Shell(script)
        self.addCleanup(sh.close)
        ctl = sh.write("var/wazuh-manager/bin/wazuh-manager-control",
                       "#!/bin/sh\necho 'wazuh-manager-apid is running...'\necho 'wazuh-manager-remoted is running...'\n", base=sh.root)
        os.chmod(ctl, 0o755)
        flag = os.path.join(sh.tmp, "restarted")
        sh.stub("curl", '[ -e %s ]' % flag)
        sh.stub("systemctl", '[ "$1" = restart ] && touch %s; [ "$1" = is-active ] && echo active; exit 0' % flag)
        sh.stub("sleep")
        rc, out = sh.run("manager5_up")
        tries = sum(1 for c in sh.called() if c.startswith("curl"))
        return rc, out, tries

    def test_it_says_the_api_did_not_answer_and_waits_less(self):
        rc, out, tries = self.up(MIGRATE)
        self.assertEqual(rc, 0, out)
        self.assertIn("daemons are running but the Server API did not answer", out)
        self.assertNotIn("daemons are not running", out)
        self.assertEqual(tries, 21)                         # 20 before the restart, 1 after it



# ------------------------------------------------------------------------------------------------ 17. rpm 2, rpm 6, the sweep
SS = helpers.load(os.path.join(SRC, "settings_stage.py"), "e3_settings_stage")


class WholeOrAbsentAfterACutRpm2Rpm6(unittest.TestCase):
    """Markers and T_import_begin were 0-byte files after a cut (the sync came before the write only); T_import_begin was
    then never written again (E3-rpm SCORECARD 2, 6). The sweep for other multi-file writes a rerun trusts: the settings
    stage's saved copies, the fleet orchestrator's state, the decisions file."""
    SYNC = ('if [ -s "$BUNDLE_DIR/state/m1" ]; then echo marker-on-disk; elif [ -e "$BUNDLE_DIR/state/m1" ]; then echo marker-empty; '
            'else echo no-marker; fi >> "$BUNDLE_DIR/../sync.log"')

    def marker(self, script, mv=None):
        sh = helpers.Shell(script)
        self.addCleanup(sh.close)
        sh.stub("sync", self.SYNC)
        if mv:
            sh.stub("mv", mv)
        rc, out = sh.run("mark m1")
        log = os.path.join(sh.tmp, "sync.log")
        f = os.path.join(sh.bundle, "state", "m1")
        return (open(log).read().split() if os.path.exists(log) else []), (open(f).read() if os.path.exists(f) else None)

    def test_the_last_sync_comes_after_the_marker_is_whole(self):
        syncs, content = self.marker(MIGRATE)
        self.assertEqual(syncs[0], "no-marker")               # the step's own writes first (E2-rpm fix 03)
        self.assertEqual(syncs[-1], "marker-on-disk")
        self.assertRegex(content, r"^\d{4}-\d\d-\d\dT")

    def test_a_cut_before_the_rename_leaves_no_marker(self):
        syncs, content = self.marker(MIGRATE, mv="exit 1")
        self.assertIsNone(content)


    def test_a_0_byte_import_time_is_written_again(self):
        for script, rewritten in ((MIGRATE, True),):
            sh = helpers.Shell(script)
            self.addCleanup(sh.close)
            sh.write("state/T_import_begin", "")
            sh.run("manager5_up() { :; }; noagents() { return 1; }; im_identity")
            self.assertEqual(os.path.getsize(os.path.join(sh.bundle, "state", "T_import_begin")) > 0, rewritten, script)

    def test_the_node_steps_marker_too(self):
        n = NodeSteps(SRC)
        self.addCleanup(n.close)
        n.stub("mv", "exit 1")
        subprocess.run(["bash", "-c", "source %s; mark m1" % os.path.join(n.node, "common.sh")], env=n.env)
        self.assertFalse(os.path.exists(os.path.join(n.bundle, "state", "m1")))

    def fsyncs_before_rename(self, mod, fn):
        seen, order = [], []
        real_fsync, real_replace = os.fsync, os.replace
        with mock.patch.object(mod.os, "fsync", lambda fd: (seen.append(os.readlink("/proc/self/fd/%d" % fd)), real_fsync(fd))), \
                mock.patch.object(mod.os, "replace", lambda a, b: (order.append((list(seen), b)), real_replace(a, b))):
            fn()
        return order

    def test_the_saved_settings_are_on_disk_before_saved_json(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        live = write(os.path.join(t, "etc", "wazuh-manager.conf"), "<x/>")
        saved = os.path.join(t, "saved")
        for mod, synced in ((SS, True),):
            shutil.rmtree(saved, ignore_errors=True)
            order = self.fsyncs_before_rename(mod, lambda: mod.save_once({"wazuh-manager.conf": live}, saved))
            before = [p for p in order[-1][0]]
            self.assertEqual(os.path.join(os.path.realpath(saved), "wazuh-manager.conf") in before, synced, (mod, order))

    def test_the_fleet_state_is_synced_before_its_rename(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        p = os.path.join(t, "upgrade-state.json")
        for mod, synced in ((FU, True),):
            order = self.fsyncs_before_rename(mod, lambda: mod.save_state(p, {"agents": {"002": {"state": "requested"}}}))
            self.assertEqual(bool(order[-1][0]), synced, mod)

    def test_the_firewall_port_is_recorded_before_it_is_added(self):
        for script, want in ((MIGRATE, "RECORDED-BEFORE-ADD"),):
            sh = helpers.Shell(script)
            self.addCleanup(sh.close)
            sh.write("etc/wazuh-manager/wazuh-manager.conf", "<remote/>\n", base=sh.root)
            v = sh.write("var/wazuh-manager/bin/wazuh-manager-conf", "#!/bin/sh\nexit 0\n", base=sh.root)
            os.chmod(v, 0o755)
            sh.stub("systemctl")
            sh.stub("sleep")
            rc, out = sh.run('fw_active() { return 0; }; fw_how() { echo; }; fw_zone() { echo public; }; '
                             'fw_port() { [ -s "$STATE/fw.added" ] && echo RECORDED-BEFORE-ADD || echo ADD-UNRECORDED; return 0; }; '
                             'op_listeners')
            self.assertIn(want, out, script)

    def test_the_decisions_file_survives_a_write_cut_in_the_middle(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        for mod, kept in ((H, True),):
            write(os.path.join(t, "decisions.json"), json.dumps({"settings": {"answered": "keep"}}))
            with self.assertRaises(TypeError):
                mod.write(t, "decisions.json", {"settings": {"answered": "keep"}, "z": object()})   # dies half way
            self.assertEqual(mod.load(t, "decisions.json") is not None, kept, mod)


if __name__ == "__main__":
    unittest.main()
