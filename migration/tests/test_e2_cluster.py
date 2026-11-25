"""The E2-cluster fold: fixes 01 to 06, and the cluster gaps 4 to 6 built without a lab (the indexer stage and saved
objects in the cluster bundle, the certificate preflight per node is in test_e2_fold, the cluster finish), plus the
controller stopping a stage on a failed node step (E2-cluster product gap 1).

Node steps hard-code product paths; NodeSteps copies src/cluster/node/ into a sandbox with those paths re-pointed under
a temporary root, as helpers.Shell does for migrate.sh, and runs them with stub commands on PATH."""
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import helpers

SRC = helpers.SRC
PATHS = ["/var/lib/wazuh-indexer", "/usr/share/wazuh-indexer", "/etc/wazuh-indexer", "/var/lib/filebeat", "/usr/share/filebeat",
         "/etc/filebeat", "/var/wazuh-manager", "/etc/wazuh-manager", "/etc/wazuh-dashboard", "/var/ossec", "/home/ec2-user", "/root/mig-work"]


def write(p, content, mode=None):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb" if isinstance(content, bytes) else "w") as f:
        f.write(content)
    if mode:
        os.chmod(p, mode)
    return p


def tgz(path, members, gz=True):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with tarfile.open(path, "w:gz" if gz else "w") as t:
        for name, data in members.items():
            i = tarfile.TarInfo(name)
            i.size = len(data)
            t.addfile(i, io.BytesIO(data))


class NodeSteps:
    def __init__(self, tree, src=None):
        self.t = tempfile.mkdtemp(prefix="node-")
        self.root, self.bin, self.node = (os.path.join(self.t, x) for x in ("root", "bin", "node"))
        self.bundle = os.path.join(self.t, "bundle")
        for d in (self.root, self.bin, self.node):
            os.makedirs(d)
        nd = os.path.join(tree, "cluster", "node")
        for f in os.listdir(nd):
            if f.endswith(".sh"):
                txt = open(os.path.join(nd, f)).read()
                for p in PATHS:
                    txt = txt.replace(p, self.root + p)
                for a, b in ((" -C / ", " -C %s/ " % self.root), (" -C /\n", " -C %s/\n" % self.root), (" -C /;", " -C %s/;" % self.root)):
                    txt = txt.replace(a, b)
                write(os.path.join(self.node, f), txt, 0o755)
        self.calls = os.path.join(self.t, "calls.log")
        open(self.calls, "w").close()
        self.env = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], BUNDLE_DIR=self.bundle, F3=os.path.join(self.t, "f3"), MIG_BUNDLE_ROOTS=self.t,
                        SRC=src or tree, V4_TAR=os.path.join(self.root, "home/ec2-user/v4/wazuh-install-files.tar"),
                        V5_TAR=os.path.join(self.root, "home/ec2-user/v5/wazuh-install-files.tar"), PYTHONDONTWRITEBYTECODE="1",
                        # CL1: the node steps' paths come from the work directory (MIG_HOME) and the scratch (WORK_DIR);
                        # pointed where the earlier lab paths were re-pointed, so the earlier cases read the same files
                        MIG_HOME=os.path.join(self.root, "home/ec2-user"), WORK_DIR=os.path.join(self.root, "root/mig-work"),
                        IDENTITY_TOOL=os.path.join(self.t, "f3", "tools", "wazuh-migrate-identity.py"), MIG_TEST_ROOT=self.root, PKGFAM="rpm")   # the earlier cases stub rpm
        for c in ("systemctl", "sleep", "chown", "restorecon", "sync"):
            self.stub(c)

    def stub(self, name, body="exit 0"):
        write(os.path.join(self.bin, name), '#!/usr/bin/env bash\necho "%s $*" >> %s\n%s\n' % (name, self.calls, body), 0o755)

    def p(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))

    def run(self, step, *args, env=None):
        e = dict(self.env)
        e.update(env or {})
        r = subprocess.run(["bash", os.path.join(self.node, step)] + list(args), env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        return r.returncode, r.stdout.decode(errors="replace")

    def called(self):
        return open(self.calls).read()

    def close(self):
        shutil.rmtree(self.t, ignore_errors=True)


class _Case(unittest.TestCase):
    def node(self, tree=SRC, src=None):
        n = NodeSteps(tree, src)
        self.addCleanup(n.close)
        return n


# ------------------------------------------------------------------------------------------------ fixes 03, 04, 05
class FreezeWaitsForPidFiles03(_Case):
    def freeze(self, tree, pid):
        n = self.node(tree)
        write(n.p("/var/ossec/var/run/wazuh-db-123.pid"), "%d\n" % pid)
        write(n.p("/var/ossec/etc/ossec.conf"), "<ossec_config><cluster><node_type>master</node_type></cluster></ossec_config>")
        write(n.p("/var/ossec/logs/alerts/alerts.json"), "{}\n")
        os.makedirs(os.path.join(n.env["F3"], "tools"))
        shutil.copy(os.path.join(tree, "cluster", "alertsjson-fold.py"), os.path.join(n.env["F3"], "tools"))   # where PRE calls it
        rc, out = n.run("freeze-manager.sh", env={"NO_DRAIN": "1"})
        return rc, out, os.path.exists(n.p("/var/ossec/var/run/wazuh-db-123.pid"))

    def test_a_stale_pid_file_is_recorded_and_removed_before_the_export(self):
        rc, out, left = self.freeze(SRC, 999999)
        self.assertEqual(rc, 0, out)
        self.assertIn("stale pid file after the stop", out)
        self.assertFalse(left)

    def test_a_live_manager_process_stops_the_freeze(self):
        p = subprocess.Popen(["sleep", "60"])
        self.addCleanup(p.kill)
        rc, out, left = self.freeze(SRC, p.pid)
        self.assertNotEqual(rc, 0)
        self.assertIn("still alive 60 s after the stop", out)



class RemoveRefusesAManagerWithoutExport04(_Case):
    def remove(self, tree):
        n = self.node(tree)
        write(n.p("/var/ossec/bin/wazuh-control"), "#!/bin/sh\n", 0o755)
        write(n.p("/var/ossec/etc/ossec.conf"), "<ossec_config/>")
        write(n.p("/home/ec2-user/v4/wazuh-install.sh"), 'echo "ASSISTANT $*" >> %s\n' % n.calls)
        n.stub("rpm", "exit 1")
        n.stub("pgrep", "exit 1")
        return n.run("remove4x.sh") + (n.called(),)

    def test_a_manager_node_with_no_export_is_not_removed(self):
        rc, out, calls = self.remove(SRC)
        self.assertNotEqual(rc, 0)
        self.assertIn("no completed export", out)
        self.assertNotIn("ASSISTANT", calls)



class FoldPlanWithoutFilebeatRegistry05(unittest.TestCase):
    def plan(self, tree):
        with tempfile.TemporaryDirectory() as d:
            write(os.path.join(d, "alerts.json"), '{"a":1}\n')
            r = subprocess.run(["python3", os.path.join(tree, "cluster", "alertsjson-fold.py"), "plan", os.path.join(d, "alerts.json"),
                                os.path.join(d, "no-registry", "log.json")], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            return r.returncode, r.stdout.decode()

    def test_no_registry_means_offset_zero(self):
        rc, out = self.plan(SRC)
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(out)["filebeat_offset"], 0)



# ------------------------------------------------------------------------------------------------ fix 06
class FilebeatKeystoreAndModule06(_Case):
    def test_the_export_archives_the_keystore_and_the_module(self):
        for tree, want in ((SRC, True),):
            n = self.node(tree)
            write(n.p("/var/lib/filebeat/filebeat.keystore"), b"ks")
            write(n.p("/usr/share/filebeat/module/wazuh/module.yml"), "m")
            write(n.p("/var/ossec/etc/ossec.conf"), "<ossec_config/>")
            os.makedirs(n.p("/var/ossec/ruleset/rules"))
            os.makedirs(n.p("/var/ossec/logs/alerts"))
            write(n.env["V4_TAR"], b"tar")
            write(os.path.join(n.env["F3"], "tools", "wazuh-migrate-identity.py"), "import os, sys\nos.makedirs(sys.argv[2], exist_ok=True)\nprint('exported')\n")
            n.stub("systemctl", "exit 3")
            n.stub("rpm", "exit 0")
            rc, out = n.run("export-manager.sh", "master")
            self.assertEqual(rc, 0, out)
            r = os.path.join(n.bundle, "v4", "rollback")
            self.assertEqual(os.path.exists(os.path.join(r, "filebeat-keystore.tar.gz")), want, tree)
            self.assertEqual(os.path.exists(os.path.join(r, "filebeat-module-wazuh.tar.gz")), want, tree)

    def test_repair_puts_back_what_a_cut_reinstall_left_missing(self):
        n = self.node()
        r = os.path.join(n.bundle, "v4", "rollback")
        os.makedirs(r)
        tgz(os.path.join(r, "filebeat-keystore.tar.gz"), {"var/lib/filebeat/filebeat.keystore": b"KS"})     # as export-manager.sh writes them
        tgz(os.path.join(r, "filebeat-module-wazuh.tar.gz"), {"usr/share/filebeat/module/wazuh/module.yml": b"M"})
        tgz(os.path.join(r, "etc-filebeat.tar.gz"), {"etc/filebeat/filebeat.yml": b"F"})    # E3 fold: the repair now checks filebeat.yml too
        n.stub("rpm", "exit 0")
        n.stub("filebeat", 'echo "talk to server... OK"')
        n.stub("systemctl", '[ "$1" = is-active ] && { [ "$2" = -q ] && exit 0; echo active; }; exit 0')
        rc, out = n.run("filebeat-repair.sh")
        self.assertEqual(rc, 0, out)
        self.assertEqual(open(n.p("/var/lib/filebeat/filebeat.keystore"), "rb").read(), b"KS")
        self.assertTrue(os.path.exists(n.p("/usr/share/filebeat/module/wazuh/module.yml")))
        self.assertIn("Filebeat keystore was missing: from the bundle", out)

    def test_the_restore_calls_the_repair(self):
        txt = open(os.path.join(SRC, "cluster", "node", "goback-restore-manager.sh")).read()
        self.assertIn("filebeat-repair.sh", txt)
        self.assertIn("filebeat-keystore filebeat-module-wazuh", txt)


# ------------------------------------------------------------------------------------------------ fixes 01, 02
class MergedStagesOnTheCluster01(_Case):
    def test_history_from_the_master_writes_the_registry_and_stamps_groups(self):
        n = self.node()
        fake = os.path.join(n.t, "fakesrc")
        write(os.path.join(fake, "history_load.py"), "import json, sys\njson.dump(sys.argv[1:], open(%r, 'w'))\n" % os.path.join(n.t, "argv.json"))
        n.env["SRC"] = fake
        write(os.path.join(n.bundle, "identity", "manifest.json"), json.dumps({"agents": [{"id": 2, "name": "ag1", "groups": ["default", "pci"]}]}))
        write(n.p("/etc/wazuh-manager/certs/indexer-ca.pem"), "CA")
        write(n.p("/etc/wazuh-manager/wazuh-manager.conf"), "<cluster>\n<name>wazuh</name>\n</cluster>\n")
        tgz(n.env["V5_TAR"], {"wazuh-install-files/credentials.env": b'WAZUH_INDEXER_ADMIN_PASSWORD="x"\n'})
        rc, out = n.run("history5-master.sh", "https://idx1:9200", "status")
        self.assertEqual(rc, 0, out)
        reg = json.load(open(os.path.join(n.bundle, "history-registry.json")))
        self.assertEqual(reg["agents"], {"002": {"name": "ag1", "groups": ["default", "pci"]}})
        argv = json.load(open(os.path.join(n.t, "argv.json")))
        self.assertIn("--agent-registry", argv)
        self.assertEqual(argv[argv.index("--cluster-name") + 1], "wazuh")

    def test_the_identity_stage_replaces_the_identity_tools_import_on_the_master(self):
        txt = open(os.path.join(SRC, "cluster", "node", "identity-stage-master.sh")).read()
        for s in ('"$S/identity_stage.py" run', '"$S/identity_stage.py" verify', 'restored-pending-restart', "wait_clusterd"):
            self.assertIn(s, txt)

    def test_the_fleet_step_holds_no_lab_address_02(self):
        # CL1: the fleet step is agents-node.sh (fleet-upgrade.sh delegates to it), with no lab or nightly address
        txt = open(os.path.join(SRC, "cluster", "node", "fleet-upgrade.sh")).read() + open(os.path.join(SRC, "cluster", "node", "agents-node.sh")).read()
        self.assertNotIn("amazonaws.com", txt)
        self.assertNotIn("nightly", txt)
        self.assertIn('[ -z "${LISTENER_HOST:-}" ] || XARGS+=(--listener-host "$LISTENER_HOST")', txt)
        self.assertIn('"$HERE/fleet-upgrade.py"', txt)

    def test_node_steps_run_the_shipped_copies(self):
        for f in ("freeze-manager.sh", "fold-alertsjson.sh", "filebeat-stop.sh", "goback-fold-4x.sh"):
            self.assertIn('"$SRC/cluster/alertsjson-fold.py"', open(os.path.join(SRC, "cluster", "node", f)).read(), f)


# ------------------------------------------------------------------------------------------------ gap 4
class IndexerSecurityInTheClusterBundleGap4(_Case):
    def setup_idx(self):
        n = self.node()
        fake = os.path.join(n.t, "fakesrc")
        write(os.path.join(fake, "mig_helper.py"), "import os, sys\n"
              "if sys.argv[1] == 'source-version': sys.exit(0)   # OF1 item 12: rpm says 4.14.10 here (SourceIsTheLatest414Item12 tests the check)\n"
              "os.makedirs(sys.argv[2], exist_ok=True)\n"
              "open(os.path.join(sys.argv[2], 'internalusers.json'), 'w').write('{}')\nassert os.environ['V4_INDEXER_ADMIN_PASSWORD'] == 'adminpw'\n")
        write(os.path.join(fake, "indexer_stage.py"), "import os, sys\nb = sys.argv[sys.argv.index('--bundle') + 1]\n"
              "os.makedirs(os.path.join(b, 'indexer'), exist_ok=True)\nopen(os.path.join(b, 'indexer', 'users.json'), 'w').write(' '.join(sys.argv[1:]))\n")
        n.env["SRC"] = fake
        write(n.p("/usr/share/wazuh-indexer/bin/indexer-security-init.sh"),
              '#!/bin/bash\necho "INIT $*" >> %s\nfor a in "$@"; do case "$a" in *-backup*) d=$(echo "$a" | sed "s/.*-backup \\([^ ]*\\).*/\\1/"); '
              'echo users > "$d/internal_users.yml"; echo roles > "$d/roles.yml";; esac; done\n' % n.calls, 0o755)
        os.makedirs(n.p("/var/lib/wazuh-indexer"))
        os.makedirs(n.p("/etc/wazuh-indexer/opensearch-security"))
        for f in ("root-ca.pem", "admin.pem", "admin-key.pem"):
            write(n.p("/etc/wazuh-indexer/certs/" + f), "c")
        tgz(n.env["V4_TAR"], {"wazuh-install-files/wazuh-passwords.txt": b"  indexer_username: 'admin'\n  indexer_password: 'adminpw'\n"})
        n.stub("rpm", 'echo 4.14.10-1')
        return n

    def test_export_then_restore4_on_node_1(self):
        n = self.setup_idx()
        rc, out = n.run("indexer-security.sh", "export")
        self.assertEqual(rc, 0, out)
        for f in ("indexer-security/rest/internalusers.json", "indexer-security/backup/internal_users.yml", "indexer/users.json"):
            self.assertTrue(os.path.exists(os.path.join(n.bundle, f)), f)
        self.assertIn("--cert %s" % n.p("/etc/wazuh-indexer/certs/admin.pem"), open(os.path.join(n.bundle, "indexer", "users.json")).read())
        man = open(os.path.join(n.bundle, "MANIFEST.sha256")).read()
        self.assertIn("indexer-security/backup/roles.yml", man)          # remove4x.sh verifies this node's bundle before the removal
        rc, out = n.run("indexer-security.sh", "restore4")
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.exists(n.p("/etc/wazuh-indexer/opensearch-security/internal_users.yml")))
        self.assertEqual(n.called().count("INIT"), 2)                      # the backup, then securityadmin with the restored files

    def test_restore4_refuses_a_changed_backup(self):
        n = self.setup_idx()
        n.run("indexer-security.sh", "export")
        write(os.path.join(n.bundle, "indexer-security", "backup", "roles.yml"), "tampered")
        rc, out = n.run("indexer-security.sh", "restore4")
        self.assertNotEqual(rc, 0)
        self.assertIn("does not match its manifest", out)

    def test_import_uses_the_50_certificate_from_the_install_files_when_the_node_has_none(self):
        n = self.setup_idx()
        n.run("indexer-security.sh", "export")
        for f in ("root-ca.pem", "admin.pem", "admin-key.pem"):
            os.unlink(n.p("/etc/wazuh-indexer/certs/" + f))
        tgz(n.env["V5_TAR"], {"wazuh-install-files/" + f: b"c5" for f in ("root-ca.pem", "admin.pem", "admin-key.pem")})
        rc, out = n.run("indexer-security.sh", "import")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(os.path.join(n.bundle, "state", "certs-tmp")))   # the extracted pair is removed

    def test_saved_objects_go_into_the_masters_bundle_and_back(self):
        n = self.node()
        fake = os.path.join(n.t, "fakesrc")
        write(os.path.join(fake, "mig_helper.py"), "import json, os, sys\nopen(%r, 'a').write(json.dumps([sys.argv[1:], {k: v for k, v in os.environ.items() if k.startswith('MIG_')}]) + '\\n')\n"
              "sys.argv[1] == 'export-saved-objects' and open(sys.argv[2], 'w').write('{}\\n')\n" % os.path.join(n.t, "helper.log"))
        n.env["SRC"] = fake
        tgz(n.env["V4_TAR"], {"wazuh-install-files/wazuh-passwords.txt": b"  indexer_username: 'admin'\n  indexer_password: 'adminpw'\n"})
        tgz(n.env["V5_TAR"], {"wazuh-install-files/credentials.env": b'WAZUH_INDEXER_ADMIN_PASSWORD="pw5"\n'})
        self.assertEqual(n.run("dashboard-objects.sh", "export", "https://dash:443")[0], 0)
        self.assertTrue(os.path.exists(os.path.join(n.bundle, "dashboard", "saved-objects.ndjson")))
        self.assertEqual(n.run("dashboard-objects.sh", "import5", "https://dash:443", "10.0.0.1")[0], 0)
        log = [json.loads(l) for l in open(os.path.join(n.t, "helper.log"))]
        self.assertEqual(log[0][1]["MIG_DASH4_URL"], "https://dash:443")
        self.assertEqual((log[1][0][0], log[1][1]["MIG_DASH5_URL"], log[1][1]["MIG_IDX5_HOST"], log[1][1]["MIG_IDX5_PASSWORD"]),
                         ("import-saved-objects", "https://dash:443", "10.0.0.1", "pw5"))
        n.stub("curl", 'echo -n 200')
        rc, out = n.run("dashboard-objects.sh", "import4", "https://dash:443")
        self.assertEqual(rc, 0, out)
        self.assertIn("_import?overwrite=true", n.called())



# ------------------------------------------------------------------------------------------------ gap 6
class ClusterFinishGap6(_Case):
    STATUS = {"yes": "legacy channel can be closed: YES (no pre-5.0 agent on record and no legacy session)\n",
              "nc": "agents not on 5.x in the registry: 1: 001 (None, never_connected)\nlegacy TCP sessions per node: wazuh-1=0, wazuh-2=0\nlegacy channel can be closed: NO\n",
              "old": "agents not on 5.x in the registry: 1: 004 (v4.14.10, active)\nlegacy TCP sessions per node: wazuh-1=0, wazuh-2=1\nlegacy channel can be closed: NO\n"}

    def decide(self, case, never=None):
        n = self.node()
        write(os.path.join(n.node, "fleet-upgrade.sh"), "#!/bin/bash\nprintf '%s'\n" % self.STATUS[case], 0o755)
        rc, out = n.run("finish-node.sh", "legacy-decide", env={"NEVER_CONNECTED_AT_FINISH": never} if never else None)
        return rc, out, n

    def test_close_when_no_agent_below_50_remains(self):
        rc, out, n = self.decide("yes")
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.exists(os.path.join(n.bundle, "state", "legacy.close_ok")))

    def test_keep_while_a_4x_agent_or_session_remains(self):
        rc, out, n = self.decide("old")
        self.assertEqual(rc, 3, out)
        self.assertIn("keep legacy: 004", open(os.path.join(n.bundle, "state", "legacy.open")).read())

    def test_never_connected_agents_keep_by_default_close_by_decision(self):
        self.assertEqual(self.decide("nc")[0], 3)
        self.assertEqual(self.decide("nc", "close")[0], 0)

    def test_legacy_close_needs_the_decision_and_checks_the_ports(self):
        n = self.node()
        conf = write(n.p("/etc/wazuh-manager/wazuh-manager.conf"), "<remote>\n<legacy>\n<enabled>yes</enabled>\n</legacy>\n</remote>\n")
        write(n.p("/var/wazuh-manager/bin/wazuh-manager-conf"), "#!/bin/sh\nexit 0\n", 0o755)
        write(n.p("/var/wazuh-manager/logs/wazuh-manager.log"), ("2026/11/24 11:06:01 wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: Consumer 'x' is ready. Starting feed download.\n"
                 "2026/11/24 11:13:55 wazuh-manager-modulesd:vulnerability-scanner: INFO: CVE feed fully loaded.\n"))   # rule 14: the feed has loaded
        self.assertNotEqual(n.run("finish-node.sh", "legacy-close")[0], 0)
        n.stub("ss", 'echo "LISTEN 0 4096 0.0.0.0:1517 0.0.0.0:*"; echo "LISTEN 0 4096 0.0.0.0:1516 0.0.0.0:*"')
        rc, out = n.run("finish-node.sh", "legacy-close", "decided")
        self.assertEqual(rc, 0, out)
        self.assertIn("<enabled>no</enabled>", open(conf).read())
        self.assertTrue(os.path.exists(conf + ".before-legacy-off"))
        n.stub("ss", 'echo "LISTEN 0 4096 0.0.0.0:1514 0.0.0.0:*"; echo "LISTEN 0 4096 0.0.0.0:1517 0.0.0.0:*"')
        rc, out = n.run("finish-node.sh", "legacy-close", "decided")
        self.assertNotEqual(rc, 0)
        self.assertIn("a legacy port is still open", out)

    def test_secrets_of_a_cluster_bundle(self):
        n = self.node()
        key = "0123456789abcdef0123456789abcdef01234567"
        tgz(os.path.join(n.bundle, "v4", "rollback", "var-ossec.tar.gz"), {"var/ossec/etc/client.keys": ("002 ag1 any %s\n" % key).encode()})
        write(os.path.join(n.bundle, "v4.gen1", "alerts", "alerts.json"), "{}\n")
        write(os.path.join(n.bundle, "logs", "x.log"), "kept\n")
        rc, out = n.run("finish-node.sh", "secrets")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(os.path.join(n.bundle, "v4", "rollback")))
        self.assertFalse(os.path.exists(os.path.join(n.bundle, "v4.gen1")))            # bundle generations hold keys too
        write(os.path.join(n.bundle, "logs", "leak.log"), "key %s\n" % key)
        tgz(os.path.join(n.bundle, "v4", "rollback", "var-ossec.tar.gz"), {"var/ossec/etc/client.keys": ("002 ag1 any %s\n" % key).encode()})
        shutil.copy(os.path.join(n.bundle, "v4", "rollback", "var-ossec.tar.gz"), os.path.join(n.bundle, "logs", "copy.tgz"))
        rc, out = n.run("finish-node.sh", "secrets")
        self.assertNotEqual(rc, 0)
        self.assertIn("key of agent 002 in", out)



# ------------------------------------------------------------------------------------------------ product gap 1 (controller)
class ControllerStopsOnAFailedStep(unittest.TestCase):



    def test_every_new_node_step_parses_and_has_a_stage(self):
        k5 = open(os.path.join(SRC, "migrate-cluster.sh")).read()     # CL1: the stages are the cluster command's now
        for f in ("indexer-security.sh", "dashboard-objects.sh", "finish-node.sh", "identity-stage-master.sh", "history5-master.sh", "agents-node.sh"):
            self.assertIn(f, k5, f)
            self.assertEqual(subprocess.run(["bash", "-n", os.path.join(SRC, "cluster", "node", f)]).returncode, 0, f)


if __name__ == "__main__":
    unittest.main()
