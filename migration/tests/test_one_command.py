"""The one command: migrate.sh with no command (or `next`) runs to the next point that needs the person, stops there with
exit 3, one question and its decisions file, and continues on the next call. The advanced commands it runs are replaced
by a stub (nx_child) that records the call and does what the case says: write markers, write a question, fail."""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock

import helpers

SRC = helpers.SRC
NF = helpers.load(os.path.join(SRC, "next_flow.py"), "next_flow_t")

STUB = r'''
nx_child() { echo "$*" >> "$BUNDLE_DIR/children.log"; mkdir -p "$STATE"
  local m; for m in $(eval echo "\${MARK_$(echo "$1${2:+_$3}" | tr -c 'A-Za-z0-9\n' '_')}"); do stamp "$m"; done
  local q; q=$(eval echo "\${ASK_$(echo "$1${2:+_$3}" | tr -c 'A-Za-z0-9\n' '_')}")
  [ -z "$q" ] || python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)) if __import__("os").path.exists(p) else {}; d.update(json.loads(sys.argv[2])); json.dump(d, open(p,"w"))' "$MIGRATION_DECISIONS" "$q"
  return $(eval echo "\${RC_$(echo "$1${2:+_$3}" | tr -c 'A-Za-z0-9\n' '_'):-0}"); }
'''
ALL_RUN = "phase.assess phase.precopy freeze.stop_manager phase.freeze phase.verify_bundle phase.replace phase.import phase.open phase.verify phase.history"
SETTINGS_Q = {"settings": {"ossec.conf:/x[1]": {"action": None, "question": {"option": "remote.queue_size", "asks": "a value 5.0 refuses",
                                                                              "answers": {"keep": "k", "omit": "o"}}}}}


class OneCommandAllInOne(unittest.TestCase):
    def setUp(self):
        self.sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(self.sh.close)
        self.dec = os.path.join(self.sh.bundle, "decisions.json")
        self.files = os.path.join(self.sh.tmp, "inputs")
        os.makedirs(os.path.join(self.files, "rm", "rmig"))
        for f in ("files.tar", "id.py"):
            open(os.path.join(self.files, f), "w").close()

    def next(self, env=None, answers=None):
        e = {"V4_INSTALL_FILES_TAR": os.path.join(self.files, "files.tar"), "IDENTITY_TOOL": os.path.join(self.files, "id.py"),
             "RMIG_DIR": os.path.join(self.files, "rm"), "CLUSTER_HOME": os.path.join(self.sh.tmp, "cluster-home"),
             "WM_SELF": "./wazuh-migrate.sh"}
        e.update(env or {})
        rc, out = self.sh.run(STUB + "cmd_next", env=e)
        return rc, out

    def children(self):
        p = os.path.join(self.sh.bundle, "children.log")
        return open(p).read().splitlines() if os.path.exists(p) else []

    def answer(self, f):
        d = json.load(open(self.dec))
        f(d)
        json.dump(d, open(self.dec, "w"))

    def test_an_open_settings_question_stops_before_the_outage(self):
        rc, out = self.next({"ASK_run_precopy": json.dumps(SETTINGS_Q), "RC_run_precopy": "3"})
        self.assertEqual(rc, 3, out)
        self.assertIn("QUESTION: remote.queue_size: a value 5.0 refuses", out)
        self.assertIn("answer in: %s" % self.dec, out)
        self.assertIn("run './wazuh-migrate.sh' again", out)
        self.assertEqual(self.children(), ["run --through precopy"])          # the outage (run without --through) never starts

    def test_a_question_still_open_after_a_passing_precopy_also_stops_it(self):
        rc, out = self.next({"ASK_run_precopy": json.dumps({"ruleset": {"version": 1, "review": None}}), "MARK_run_precopy": "phase.precopy"})
        self.assertEqual(rc, 3, out)
        self.assertIn("\"review\" to \"accepted\"", out)
        self.assertEqual(self.children(), ["run --through precopy"])

    def test_the_point_of_no_return_is_a_question_then_the_rest_runs_alone(self):
        env = {"MARK_run_precopy": "phase.precopy", "MARK_run": ALL_RUN, "MARK_confirm_no_return": "confirm.no_return",
               "MARK_agents": "phase.agents", "MARK_finish": "phase.finish"}
        rc, out = self.next(env)
        self.assertEqual(rc, 3, out)
        self.assertIn("POINT OF NO RETURN", out)
        self.assertIn("'./wazuh-migrate.sh back' returns to 4.14.x", out)
        self.assertEqual(self.children(), ["run --through precopy", "run"])
        rc, out = self.next(env)                                               # unanswered: the same question, nothing run
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.children(), ["run --through precopy", "run", "run"])
        self.answer(lambda d: d["point-of-no-return"][0].update(action="confirm"))
        rc, out = self.next(env)
        self.assertEqual(rc, 0, out)
        self.assertIn("MIGRATION FINISHED", out)
        self.assertEqual(self.children()[-4:], ["run", "confirm-no-return", "agents", "finish"])
        rc, out = self.next(env)                                               # finished: running it again changes nothing
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.children()), 7)

    def test_raw_at_finish_is_asked_and_the_answer_continues(self):
        for m in ALL_RUN.split() + ["confirm.no_return", "phase.agents"]:
            self.sh.write("state/" + m, "t")
        q = {"unclassified-finish": [{"id": "raw-at-finish", "action": None, "choices": ["activated", "keep-raw", "accept-loss"],
                                      "question": "The migrated rules are not active"}]}
        rc, out = self.next({"ASK_finish": json.dumps(q), "RC_finish": "3"})
        self.assertEqual(rc, 3, out)
        self.assertIn("QUESTION: The migrated rules are not active", out)
        self.assertIn('"activated" or "keep-raw" or "accept-loss"', out)
        self.assertEqual(self.children(), ["finish"])                         # agents is not run again
        self.answer(lambda d: d["unclassified-finish"][0].update(action="keep-raw"))
        rc, out = self.next({"MARK_finish": "phase.finish"})
        self.assertEqual(rc, 0, out)
        self.assertIn("MIGRATION FINISHED", out)

    def test_a_failure_says_what_failed_and_that_the_same_command_continues(self):
        self.sh.write("results/replace.install5.json", {"step": "replace.install5", "description": "install 5.0 with the assistant",
                                                        "exit": 1, "result": "failed"})
        self.sh.write("results/replace.install5.log", "x")
        rc, out = self.next({"MARK_run_precopy": "phase.precopy", "RC_run": "1"})
        self.assertEqual(rc, 1, out)
        self.assertIn("=== FAILED: install 5.0 with the assistant (step replace.install5, exit 1)", out)
        self.assertIn("Fix the cause and run './wazuh-migrate.sh' again", out)

    def test_exit_3_of_a_child_without_a_question_is_a_failure_not_a_question(self):
        rc, out = self.next({"MARK_run_precopy": "phase.precopy", "RC_run": "3"})
        self.assertEqual(rc, 1, out)
        self.assertNotIn("QUESTION", out)

    def test_the_external_installer_wait_is_exit_10(self):
        rc, out = self.next({"MARK_run_precopy": "phase.precopy", "RC_run": "10"})
        self.assertEqual(rc, 10, out)
        self.assertIn("WAITING for your deployment tool", out)

    def test_4x_agents_left_is_a_wait_and_the_next_call_upgrades_them(self):
        for m in ALL_RUN.split() + ["confirm.no_return", "phase.agents"]:
            self.sh.write("state/" + m, "t")
        self.sh.write("state/legacy.open", "keep legacy: 004 (v4.14.10, active)\n")
        rc, out = self.next()
        self.assertEqual(rc, 4, out)
        self.assertIn("WAITING: agents still on 4.x (004 (v4.14.10, active))", out)   # F7 wording: names them
        self.assertEqual(self.children(), ["agents", "finish"])
        os.remove(os.path.join(self.sh.bundle, "state", "legacy.open"))
        rc, out = self.next({"MARK_finish": "phase.finish"})
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.children(), ["agents", "finish", "finish"])

    def test_never_connected_agents_only_end_the_migration(self):
        for m in ALL_RUN.split() + ["confirm.no_return", "phase.agents"]:
            self.sh.write("state/" + m, "t")
        self.sh.write("state/legacy.open", "keep never-connected: 007 \n")
        rc, out = self.next()
        self.assertEqual(rc, 0, out)
        self.assertIn("MIGRATION FINISHED, with the legacy ports kept open", out)
        self.assertEqual(self.children(), ["finish"])

    def test_a_missing_input_is_asked_once_and_the_answer_is_used(self):
        env = {"V4_INSTALL_FILES_TAR": "", "MARK_run_precopy": "phase.precopy", "RC_run": "1"}
        rc, out = self.next(env)
        self.assertEqual(rc, 3, out)
        self.assertIn("Where is wazuh-install-files.tar", out)
        self.assertEqual(self.children(), [])
        self.answer(lambda d: d["inputs"][0].update(path=os.path.join(self.files, "files.tar")))
        rc, out = self.next(env)
        self.assertEqual(self.children(), ["run --through precopy", "run"])

    def test_after_going_back_a_new_attempt_starts(self):
        # F7: no longer a refusal asking for BUNDLE_DIR; the earlier bundle is kept beside the new one (test_f7_fold)
        self.sh.write("state/back.done", "t")
        rc, out = self.next()
        self.assertNotIn("FATAL", out)
        self.assertIn("went back to 4.x", out)
        self.assertIn("NEW ATTEMPT", out)
        self.assertEqual(self.children(), ["run --through precopy", "run"])

    def test_role_loss_answer_passes_the_accept_flag(self):
        rc, out = self.sh.run('role_loss_args "%s"' % self.dec)
        self.assertEqual(out.strip(), "")
        NF.cmd_role_loss(self.dec, "/nonexistent.json")
        self.answer(lambda d: d["history-roles"][0].update(action="accept"))
        rc, out = self.sh.run('role_loss_args "%s"' % self.dec)
        self.assertEqual(out.strip(), "--accept-role-loss")
        rc, out = self.sh.run('role_loss_args "%s"' % self.dec, env={"ACCEPT_ROLE_LOSS": "1"})
        self.assertEqual(out.strip(), "--accept-role-loss")


class ClusterDetection(unittest.TestCase):
    CONF = "<ossec_config>\n<cluster>\n<name>wazuh</name>\n<node_name>%s</node_name>\n<node_type>%s</node_type>\n<nodes>\n<node>10.0.0.21</node>\n</nodes>\n<disabled>%s</disabled>\n</cluster>\n</ossec_config>\n"

    def role(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write(text)
        self.addCleanup(os.remove, f.name)
        p = subprocess.run([sys.executable, os.path.join(SRC, "next_flow.py"), "cluster-role", f.name], stdout=subprocess.PIPE)
        return p.stdout.decode().strip()

    def test_roles(self):
        self.assertEqual(self.role(self.CONF % ("wazuh-1", "master", "no")), "master")
        self.assertEqual(self.role(self.CONF % ("wazuh-2", "worker", "no")), "worker 10.0.0.21")
        self.assertEqual(self.role(self.CONF % ("wazuh-1", "master", "yes")), "single")
        self.assertEqual(self.role("<ossec_config></ossec_config>"), "single")
        self.assertEqual(self.role("<!-- <cluster><disabled>no</disabled></cluster> -->" + self.CONF % ("a", "master", "yes")), "single")

    def test_next_on_a_master_goes_to_the_cluster_flow_and_refuses_a_worker(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        os.makedirs(os.path.join(sh.root, "var/ossec/etc"))
        open(os.path.join(sh.root, "var/ossec/etc/ossec.conf"), "w").write(self.CONF % ("wazuh-1", "master", "no"))
        env = {"CLUSTER_HOME": os.path.join(sh.tmp, "ch")}
        rc, out = sh.run('rm -rf "$STATE"; nx_where', env=env)
        self.assertEqual(out.strip(), "cluster-home")
        open(os.path.join(sh.root, "var/ossec/etc/ossec.conf"), "w").write(self.CONF % ("wazuh-2", "worker", "no"))
        rc, out = sh.run('rm -rf "$STATE"; cmd_next', env=env)
        self.assertNotEqual(rc, 0)
        self.assertIn("run the tool on the master", out)
        rc, out = sh.run('nx_where', env=env)                                  # a run already started here stays all-in-one
        self.assertEqual(out.strip(), "all-in-one")
        rc, out = sh.run('nx_where', env=dict(env, NEXT_INVENTORY="/x/inv.json"))
        self.assertEqual(out.strip(), "cluster /x/inv.json")


CONFIG_4X = """nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "10.0.0.11"
    - name: node-2
      ip: 10.0.0.12
  server:
    - name: wazuh-1
      ip: "10.0.0.21"
      node_type: master
    - name: wazuh-2
      ip:
        - "10.0.0.22"
        - "10.0.0.122"
      node_type: worker
  dashboard:
    - name: dashboard
      ip: "10.0.0.31"
"""
PASSWORDS = """# Admin user for the web user interface and Wazuh indexer.
  indexer_username: 'admin'
  indexer_password: 'Aa1-not-a-real-one'

# Password for wazuh API user
  api_username: 'wazuh'
  api_password: 'Bb2-not-a-real-one'
"""


class ClusterInventory(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)

    def tar(self):
        d = os.path.join(self.t, "wazuh-install-files")
        os.makedirs(d)
        open(os.path.join(d, "config.yml"), "w").write(CONFIG_4X)
        open(os.path.join(d, "wazuh-passwords.txt"), "w").write(PASSWORDS)
        p = os.path.join(self.t, "wazuh-install-files.tar")
        with tarfile.open(p, "w") as t:
            t.add(d, "wazuh-install-files")
        return p

    def test_config_yml_is_parsed(self):
        n = NF.parse_config_yml(CONFIG_4X)
        self.assertEqual([x["name"] for x in n["indexer"]], ["node-1", "node-2"])
        self.assertEqual(n["indexer"][1]["ip"], "10.0.0.12")
        self.assertEqual(n["server"][1], {"name": "wazuh-2", "ip": "10.0.0.22", "node_type": "worker"})

    def test_install_files_give_the_config_and_the_api_password(self):
        conf, pw = NF.install_files(self.tar())
        self.assertIn("node_type: master", conf)
        self.assertEqual(pw[("api", "wazuh")], "Bb2-not-a-real-one")

    def test_the_inventory_takes_the_managers_from_the_cluster_api(self):
        api = [{"name": "wazuh-2", "role": "worker", "address": "10.0.0.22"}, {"name": "wazuh-1", "role": "master", "address": "10.0.0.21"},
               {"name": "wazuh-3", "role": "worker", "address": "10.0.0.23"}]
        inv = NF.build_inventory(CONFIG_4X, api, {"ruleset_tool": "/r"})
        self.assertEqual([(n["name"], n["role"]) for n in inv["nodes"]],
                         [("node-1", "indexer"), ("node-2", "indexer"), ("wazuh-1", "master"), ("wazuh-2", "worker"), ("wazuh-3", "worker"), ("dashboard", "dashboard")])
        self.assertEqual(inv["ssh"], {"user": None, "key": None})
        c5 = NF.config5(inv)
        self.assertIn("  manager:\n    - name: wazuh-1\n      ip: \"10.0.0.21\"\n      node_type: master\n", c5)
        self.assertNotIn("server:", c5)
        self.assertEqual(NF.parse_config_yml(c5)["manager"][2]["name"], "wazuh-3")

    def test_without_the_api_the_config_yml_names_the_managers(self):
        out = os.path.join(self.t, "home", "inventory.json")
        with unittest.mock.patch.object(NF, "api_nodes", side_effect=OSError("down")):
            self.assertEqual(NF.cmd_cluster_inventory(out, "--install-files", self.tar(), "--inputs", json.dumps({"ruleset_tool": "/r"})), 0)
        inv = json.load(open(out))
        self.assertEqual([n["name"] for n in inv["nodes"] if n["role"] in ("master", "worker")], ["wazuh-1", "wazuh-2"])
        self.assertEqual(inv["inputs"]["v5_config"], os.path.join(self.t, "home", "config-5.0.yml"))
        self.assertNotIn("not-a-real-one", open(out).read())
        # the inventory passes inventory.py's check once SSH access is answered
        dec = os.path.join(self.t, "home", "decisions.json")
        self.assertEqual(NF.cmd_ssh(out, dec), 3)
        self.assertEqual(NF.cmd_question(dec), 0)
        d = json.load(open(dec))
        key = os.path.join(self.t, "key")
        open(key, "w").close()
        os.chmod(key, 0o600)
        d["ssh-access"][0].update(user="root", key=key)
        json.dump(d, open(dec, "w"))
        self.assertEqual(NF.cmd_ssh(out, dec), 0)
        self.assertEqual(json.load(open(out))["ssh"]["user"], "root")
        self.assertEqual(NF.cmd_open(dec), 1)


class OneCommandOnAClusterMaster(unittest.TestCase):
    def test_inventory_ssh_question_then_the_cluster_flow(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(sh.close)
        os.makedirs(os.path.join(sh.root, "var/ossec/etc"))
        open(os.path.join(sh.root, "var/ossec/etc/ossec.conf"), "w").write(ClusterDetection.CONF % ("wazuh-1", "master", "no"))
        ci = ClusterInventory()
        ci.t = sh.tmp
        tar = ci.tar()
        os.makedirs(os.path.join(sh.tmp, "rm", "rmig"))
        open(os.path.join(sh.tmp, "id.py"), "w").close()
        home = os.path.join(sh.tmp, "ch")
        env = {"CLUSTER_HOME": home, "V4_INSTALL_FILES_TAR": tar, "IDENTITY_TOOL": os.path.join(sh.tmp, "id.py"),
               "RMIG_DIR": os.path.join(sh.tmp, "rm"), "WM_SELF": "./wazuh-migrate.sh", "MARK_run_precopy": "phase.precopy", "RC_run": "1"}
        rc, out = sh.run('rm -rf "$STATE"; ' + STUB + "cmd_next", env=env)
        self.assertEqual(rc, 3, out)
        self.assertIn("Which SSH user and private key", out)
        inv = json.load(open(os.path.join(home, "inventory.json")))
        self.assertEqual(inv["inputs"]["identity_tool"], os.path.join(home, "wazuh-migrate-identity.py"))   # a stable copy
        self.assertTrue(os.path.exists(os.path.join(home, "wazuh-migrate-identity.py")))
        d = json.load(open(os.path.join(home, "decisions.json")))
        d["ssh-access"][0].update(user="root", key="/root/.ssh/k")
        json.dump(d, open(os.path.join(home, "decisions.json"), "w"))
        rc, out = sh.run(STUB + "cmd_next", env=env)
        self.assertEqual(rc, 1, out)                                               # the stub's run fails
        self.assertEqual(open(os.path.join(sh.bundle, "children.log")).read().splitlines(), ["run --through precopy", "run"])
        self.assertTrue(os.path.exists(os.path.join(home, "cluster-state", "state", "phase.precopy")))   # the controller's state
        self.assertEqual(json.load(open(os.path.join(home, "inventory.json")))["ssh"]["user"], "root")


class DecisionQuestions(unittest.TestCase):
    def test_order_and_ruleset_questions(self):
        d = {"ruleset": {"fields": {"acme.x": {"action": None, "used_by": ["rule:1"]}, "acme.y": {"action": "drop"}},
                         "covered": {"100": {"action": None}}, "lists": {"l": {"action": None}}, "review": None},
             "settings": {"a": {"action": "keep"}}}
        qs = NF.open_questions(d)
        self.assertEqual([q[1] for q in qs], ["fields/acme.x", "review"])       # covered and lists: null is a default, not a question
        d["inputs"] = [{"id": "RMIG_DIR", "fill": ["path"], "path": None, "question": "where"}]
        self.assertEqual(NF.open_questions(d)[0][1], "RMIG_DIR")

    def test_ask_keeps_an_answer(self):
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        p = os.path.join(t, "d.json")
        NF.cmd_no_return(p, "./wazuh-migrate.sh", "all-in-one")
        self.assertEqual(NF.cmd_answer(p, "point-of-no-return", "confirm-no-return"), 1)
        d = json.load(open(p))
        d["point-of-no-return"][0]["action"] = "confirm"
        json.dump(d, open(p, "w"))
        NF.cmd_no_return(p, "./wazuh-migrate.sh", "all-in-one")
        self.assertEqual(json.load(open(p))["point-of-no-return"][0]["action"], "confirm")
        self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")


class OneFileBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = tempfile.mkdtemp()
        cls.out = os.path.join(cls.t, "wazuh-migrate.sh")
        cls.ident = os.path.join(cls.t, "wazuh-migrate-identity.py")
        open(cls.ident, "w").write("print('not the pinned one')\n")
        p = subprocess.run(["bash", os.path.join(SRC, "build-wazuh-migrate.sh"), "--out", cls.out], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cls.build = p.stdout.decode()
        assert p.returncode == 0, cls.build

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.t, True)

    def run_file(self, *args, path=None):
        p = subprocess.run(["bash", path or self.out] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode()

    def test_version_prints_the_tool_fingerprint_and_the_rmig_commit(self):
        rc, out = self.run_file("--version")
        self.assertEqual(rc, 0, out)
        fp = subprocess.run(["bash", "-c", 'source <(sed -n "/^tool_fingerprint()/p" %s/migrate.sh); HERE=%s; tool_fingerprint' % (SRC, SRC)],
                            stdout=subprocess.PIPE).stdout.decode().strip()
        self.assertIn("wazuh-migrate.sh %s (tool fingerprint)" % fp, out)
        mf = json.load(open(os.path.join(SRC, "manifest", "builds.json")))
        self.assertIn("ruleset tool commit %s" % mf["ruleset_tool"]["commit"], out)   # F8: as the person reads it
        self.assertIn("identity tool not embedded", out)                       # built without --identity

    def test_self_test_passes_and_a_changed_byte_fails_it(self):
        rc, out = self.run_file("--self-test")
        self.assertEqual(rc, 0, out)
        self.assertIn("self-test passed", out)
        bad = os.path.join(self.t, "bad.sh")
        text = open(self.out).read().splitlines(True)
        i = text.index("__WAZUH_MIGRATE_PAYLOAD__\n") + 3
        text[i] = ("B" if text[i][0] != "B" else "C") + text[i][1:]
        open(bad, "w").write("".join(text))
        rc, out = self.run_file("--self-test", path=bad)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("does not match its sha256", out)

    def test_an_identity_tool_that_is_not_the_pinned_one_is_refused(self):
        p = subprocess.run(["bash", os.path.join(SRC, "build-wazuh-migrate.sh"), "--out", os.path.join(self.t, "x.sh"), "--identity", self.ident],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not the pinned", p.stdout.decode())

    def test_the_file_runs_migrate_sh_and_removes_its_directory(self):
        d = os.path.join(self.t, "home")
        os.makedirs(d)
        env = dict(os.environ, WAZUH_MIGRATE_TMP=d)
        p = subprocess.run(["bash", self.out, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        self.assertEqual(p.returncode, 0)
        self.assertIn("runs to the next point that needs you", p.stdout.decode())
        self.assertEqual(os.listdir(d), [])

    def test_a_directory_left_by_a_killed_run_is_removed_and_a_live_one_kept(self):
        d = os.path.join(self.t, "home2")
        for name, pid in (("dead", 2 ** 22 + 7), ("live", os.getpid())):
            os.makedirs(os.path.join(d, ".wazuh-migrate." + name))
            open(os.path.join(d, ".wazuh-migrate." + name, ".pid"), "w").write("%d\n" % pid)
        p = subprocess.run(["bash", self.out, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, WAZUH_MIGRATE_TMP=d))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(os.listdir(d), [".wazuh-migrate.live"])


if __name__ == "__main__":
    unittest.main()
