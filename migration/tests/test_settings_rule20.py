"""Follow-up: the settings converter inside the flow (rules 21 and 22) and rule 20 (saved objects rolled back by
attribute)."""
import contextlib
import filecmp
import io
import json
import os
import re
import shutil
import stat
import tempfile
import unittest
import urllib.parse
from unittest import mock

import helpers

SRC = helpers.SRC
FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "settings")
CONV = os.path.join(SRC, "converter")
STOCK = os.path.join(CONV, "refs", "stock-4.14.10-ubuntu24")
BASE = os.path.join(CONV, "refs", "base-5.0.0-aio")
SS = helpers.load(os.path.join(SRC, "settings_stage.py"), "settings_stage")
H = helpers.load(os.path.join(SRC, "mig_helper.py"), "mig_helper_f2")


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="settings-")
        self.v4 = os.path.join(self.t, "v4")
        shutil.copytree(os.path.join(FX, "e1x-aio"), self.v4)
        os.unlink(os.path.join(self.v4, "decisions.json"))
        self.groups = os.path.join(self.t, "groups4")
        shutil.copytree(os.path.join(FX, "groups"), self.groups)
        self.dec = os.path.join(self.t, "decisions.json")
        self.answers = json.load(open(os.path.join(FX, "e1x-aio", "decisions.json")))

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def plan(self, base=BASE):
        return quiet(SS.main, ["plan", "--v4", self.v4, "--stock", STOCK, "--base", base, "--decisions", self.dec,
                               "--work", os.path.join(self.t, "work"), "--groups", self.groups])


class PlanAndDecisions(_Tmp):
    def test_open_questions_become_entries_and_stop_the_run(self):
        rc, out = self.plan()
        self.assertEqual(rc, 3, out)
        d = json.load(open(self.dec))
        # C4's 5 exercise questions; the four options of the removed syslog_output section are one question (F7)
        sec = "ossec.conf:/ossec_config[3]/syslog_output[1]"
        self.assertEqual(sorted(d["settings"]), sorted([i for i in self.answers if not i.startswith(sec + "/")] + [sec]))
        self.assertEqual(sorted(d["settings"][sec]["covers"]), sorted(i for i in self.answers if i.startswith(sec + "/")))
        self.assertTrue(all(e["action"] is None for e in d["settings"].values()))
        self.assertIn("DECISIONS NEEDED", out)

    def test_answers_are_kept_and_the_plan_passes(self):
        self.plan()
        d = json.load(open(self.dec))
        d["settings"].update(self.answers)
        json.dump(d, open(self.dec, "w"))
        rc, out = self.plan()
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.load(open(self.dec))["settings"]["local_internal_options.conf:/line[21]/monitord.day_wait"]["action"], "replace")

    def test_an_answer_this_run_does_not_need_is_not_passed_to_the_converter(self):
        """The converter refuses unused decision ids; the flow keeps answers for questions another base raised."""
        d = {"settings": dict(self.answers, **{"ossec.conf:/ossec_config[9]/cluster[1]/key[1]": {"action": "omit", "reason": "x"}})}
        json.dump(d, open(self.dec, "w"))
        rc, out = self.plan()
        self.assertEqual(rc, 0, out)
        # without the filtering: the converter alone refuses the same file
        os.makedirs(os.path.join(self.t, "raw"))
        json.dump(d["settings"], open(os.path.join(self.t, "raw", "d.json"), "w"))
        rc2, txt = SS._run(SS.manager_args(self.v4, STOCK, BASE) + ["--decisions", os.path.join(self.t, "raw", "d.json"), "--out", os.path.join(self.t, "raw", "o")])
        self.assertEqual(rc2, 1)
        self.assertIn("Unused decision ids", txt)

    def test_convert_refuses_while_open_and_writes_the_merged_files_when_answered(self):
        out = os.path.join(self.t, "cand")
        rc, txt = quiet(SS.main, ["convert", "--v4", self.v4, "--stock", STOCK, "--base", BASE, "--decisions", self.dec, "--out", out])
        self.assertEqual(rc, 3)
        self.assertFalse(os.path.exists(out))
        d = json.load(open(self.dec))
        d["settings"].update(self.answers)
        json.dump(d, open(self.dec, "w"))
        rc, txt = quiet(SS.main, ["convert", "--v4", self.v4, "--stock", STOCK, "--base", BASE, "--decisions", self.dec, "--out", out])
        self.assertEqual(rc, 0, txt)
        self.assertIn("wazuh_modules.manager_task_log_day_wait=10", open(os.path.join(out, "wazuh-manager-internal-options.conf")).read())
        key = lambda p: re.search(r"<key>([^<]*)</key>", open(p).read()).group(1)     # rule 21: the installed key stays
        self.assertEqual(key(os.path.join(out, "wazuh-manager.conf")), key(os.path.join(BASE, "wazuh-manager.conf")))


class StageCheckRestore(_Tmp):
    def _installed(self):
        inst = os.path.join(self.t, "installed")
        os.makedirs(inst)
        targets = {}
        for name in ("wazuh-manager.conf", "wazuh-manager-internal-options.conf", "api.yaml"):
            shutil.copy(os.path.join(BASE, name), os.path.join(inst, name))
            os.chmod(os.path.join(inst, name), 0o640)
            targets[name] = os.path.join(inst, name)
        cand = os.path.join(self.t, "cand")
        os.makedirs(cand)
        for name in targets:
            open(os.path.join(cand, name), "w").write("converted " + name + "\n")
        return inst, cand, targets

    def apply(self, cand, targets, check="true", validate=None):
        argv = ["apply", "--candidate", cand, "--saved", os.path.join(self.t, "saved"), "--targets", json.dumps(targets), "--check-cmd", check]
        if validate:
            argv += ["--validate-cmd", validate]
        return quiet(SS.main, argv)

    def test_a_failed_check_puts_the_saved_files_back_rule_22(self):
        inst, cand, targets = self._installed()
        rc, out = self.apply(cand, targets, check="false")
        self.assertEqual(rc, 1)
        self.assertIn("CHECK FAILED", out)
        for name, p in targets.items():
            self.assertTrue(filecmp.cmp(p, os.path.join(BASE, name), shallow=False), name)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o640)

    def test_a_passing_check_leaves_the_converted_files_with_the_installed_mode(self):
        inst, cand, targets = self._installed()
        rc, out = self.apply(cand, targets)
        self.assertEqual(rc, 0, out)
        for name, p in targets.items():
            self.assertEqual(open(p).read(), "converted " + name + "\n")
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o640)

    def test_the_first_saved_copy_is_kept_on_a_rerun(self):
        inst, cand, targets = self._installed()
        self.apply(cand, targets)                 # staged; a kill before the restart, then the rerun
        rc, out = self.apply(cand, targets, check="false")
        self.assertIn("already saved", out)
        self.assertTrue(filecmp.cmp(targets["api.yaml"], os.path.join(BASE, "api.yaml"), shallow=False))

    def test_a_candidate_that_does_not_validate_is_never_staged(self):
        inst, cand, targets = self._installed()
        rc, out = self.apply(cand, targets, validate="false")
        self.assertEqual(rc, 1)
        self.assertTrue(filecmp.cmp(targets["wazuh-manager.conf"], os.path.join(BASE, "wazuh-manager.conf"), shallow=False))


class GroupPasses(_Tmp):
    def run_groups(self, phase, versions=None, dry=False):
        shared = os.path.join(self.t, "shared")
        for g in os.listdir(self.groups):
            os.makedirs(os.path.join(shared, g), exist_ok=True)
        argv = ["groups", "--phase", phase, "--groups", self.groups, "--decisions", self.dec, "--work", os.path.join(self.t, "w-" + phase),
                "--shared", shared] + (["--versions", json.dumps(versions)] if versions else []) + (["--dry-run"] if dry else [])
        uploads = []
        with mock.patch.object(SS, "upload_group_conf", lambda g, data: uploads.append((g, data)) or (200, {"error": 0})):
            rc, out = quiet(SS.main, argv)
        return rc, out, uploads, shared

    def test_pre_upgrade_removes_what_4x_refuses_and_carries_named_files(self):
        rc, out, uploads, shared = self.run_groups("pre-upgrade")
        self.assertEqual(rc, 0, out)
        up = dict(uploads)
        self.assertNotIn(b"prefilter_cmd", up["c4-audit"])                 # a 4.x agent refuses its whole configuration with it
        self.assertIn(b"system_audit", up["c4-audit"])                     # kept for 4.x agents until they upgrade
        self.assertNotIn("default", up)                                    # default's agent.conf is the identity import's
        self.assertTrue(os.path.exists(os.path.join(shared, "c4-audit", "c4_audit_rcl.txt")))
        self.assertTrue(os.path.exists(os.path.join(shared, "default", "rootkit_files.txt")))

    def test_post_upgrade_only_for_groups_whose_agents_all_run_5x(self):
        _, _, _, shared = self.run_groups("pre-upgrade")
        versions = {"acme-web": {"002": "Wazuh v4.14.10"}, "c4-audit": {"001": "Wazuh v5.0.0", "002": "Wazuh v5.0.0"},
                    "default": {"001": "Wazuh v5.0.0"}}
        rc, out, uploads, shared = self.run_groups("post-upgrade", versions)
        self.assertEqual(rc, 0, out)
        up = dict(uploads)
        self.assertNotIn("acme-web", up)
        self.assertIn("agents below 5.0: ['002']", out)
        self.assertNotIn(b"system_audit", up["c4-audit"])
        self.assertFalse(os.path.exists(os.path.join(shared, "default", "rootkit_files.txt")))   # listed for deletion

    def test_major_version(self):
        self.assertEqual([SS.major(v) for v in ("Wazuh v5.0.0", "v4.14.10", None, "")], [5, 4, None, None])


class FlowWiring(unittest.TestCase):
    """The steps, in C4's order, inside the contract; absent from the copies the merge started from."""

    def test_steps_and_their_order(self):
        txt = open(os.path.join(SRC, "migrate.sh")).read()
        steps = re.findall(r"\bq?step +([a-z_.]+) ", txt)
        for s in ("precopy.settings_plan", "replace.settings_plan", "import.settings", "import.groups_pre", "finish.groups_post"):
            self.assertIn(s, steps)
        self.assertLess(steps.index("precopy.settings"), steps.index("precopy.settings_plan"))
        self.assertLess(steps.index("precopy.settings_plan"), steps.index("precopy.gate"))
        self.assertLess(steps.index("replace.gate"), steps.index("replace.settings_plan"))
        self.assertLess(steps.index("import.identity"), steps.index("import.settings"))
        self.assertLess(steps.index("import.settings"), steps.index("import.restart"))
        self.assertLess(steps.index("finish.groups_post"), steps.index("finish.secrets"))


class ImSettingsInTheScript(unittest.TestCase):
    """im_settings and im_restart of migrate.sh in a sandbox: the real converter, a stub product check."""

    def setUp(self):
        self.sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        for c in ("systemctl", "sleep", "ss", "iptables", "nft"):
            self.sh.stub(c)
        self.sh.stub("curl", "exit 7")
        r, b = self.sh.root, self.sh.bundle
        os.makedirs(os.path.join(r, "var/wazuh-manager/bin"))
        os.makedirs(os.path.join(r, "var/wazuh-manager/api/configuration"))
        os.makedirs(os.path.join(r, "etc/wazuh-manager"))
        for exe, body in (("wazuh-manager-conf", "exit 0"), ("wazuh-manager-control", 'case "$1" in check) exit ${CHECK_RC:-0};; status) echo "x is running...";; esac; exit 0')):
            p = os.path.join(r, "var/wazuh-manager/bin", exe)
            open(p, "w").write("#!/bin/bash\n" + body + "\n")
            os.chmod(p, 0o755)
        self.targets = {"wazuh-manager.conf": os.path.join(r, "etc/wazuh-manager/wazuh-manager.conf"),
                        "wazuh-manager-internal-options.conf": os.path.join(r, "etc/wazuh-manager/wazuh-manager-internal-options.conf"),
                        "api.yaml": os.path.join(r, "var/wazuh-manager/api/configuration/api.yaml")}
        for name, p in self.targets.items():
            shutil.copy(os.path.join(BASE, name), p)
        shutil.copytree(BASE, os.path.join(b, "settings/base-installed"))
        open(os.path.join(b, "settings/targets.json"), "w").write(json.dumps(self.targets))
        shutil.copytree(os.path.join(FX, "e1x-aio"), os.path.join(b, "v4/config"))
        shutil.copytree(STOCK, os.path.join(b, "v4/config/stock"))
        json.dump({"settings": json.load(open(os.path.join(FX, "e1x-aio", "decisions.json")))}, open(os.path.join(b, "decisions.json"), "w"))
        os.unlink(os.path.join(b, "v4/config/decisions.json"))

    def tearDown(self):
        self.sh.close()

    def test_failed_product_check_restores_and_stops(self):
        rc, out = self.sh.run("im_settings; echo rc=$?", env={"CHECK_RC": "1"})
        self.assertIn("rc=1", out)
        self.assertIn("CHECK FAILED", out)
        for name, p in self.targets.items():
            self.assertTrue(filecmp.cmp(p, os.path.join(BASE, name), shallow=False), name)
        self.assertFalse(os.path.exists(os.path.join(self.sh.bundle, "state/T_settings_staged")))

    def test_passing_check_stages_the_converted_files(self):
        rc, out = self.sh.run("im_settings; echo rc=$?")
        self.assertIn("rc=0", out)
        self.assertIn("wazuh_modules.manager_task_log_day_wait=10", open(self.targets["wazuh-manager-internal-options.conf"]).read())
        self.assertTrue(os.path.exists(os.path.join(self.sh.bundle, "state/T_settings_staged")))

    def test_a_manager_that_does_not_start_on_them_gets_the_saved_files_back(self):
        self.sh.run("im_settings")
        rc, out = self.sh.run("im_restart; echo rc=$?")
        self.assertIn("rc=1", out)
        self.assertIn("putting the saved installed files back", out)
        self.assertTrue(filecmp.cmp(self.targets["api.yaml"], os.path.join(BASE, "api.yaml"), shallow=False))

    def test_a_cluster_node_without_the_other_candidates_stages_nothing_rule_21(self):
        conf = self.targets["wazuh-manager.conf"]
        t = open(conf).read()
        t = re.sub(r"<cluster>.*?</cluster>", "<cluster><name>wazuh</name><node_name>m</node_name><node_type>master</node_type><key>%s</key>"
                   "<port>1516</port><bind_addr>0.0.0.0</bind_addr><nodes><node>10.0.0.1</node></nodes><disabled>no</disabled></cluster>" % ("a" * 32), t, flags=re.S)
        open(conf, "w").write(t)
        before = open(self.targets["api.yaml"]).read()
        rc, out = self.sh.run("im_settings; echo rc=$?")
        self.assertIn("rc=1", out)
        self.assertIn("cross-node check needs the other nodes' candidates", out)
        self.assertEqual(open(self.targets["api.yaml"]).read(), before)



class DecisionsFileAndStock(unittest.TestCase):
    def test_ruleset_section_put_keeps_answers_and_get_returns_them(self):
        t = tempfile.mkdtemp(prefix="dec-")
        try:
            f, rm = os.path.join(t, "decisions.json"), os.path.join(t, "rmig.json")
            json.dump({"q1": {"answer": None}}, open(rm, "w"))
            quiet(H.decisions_section, "put", f, "ruleset", rm)
            d = json.load(open(f))
            d["ruleset"]["q1"]["answer"] = "keep"
            json.dump(d, open(f, "w"))
            quiet(H.decisions_section, "put", f, "ruleset", rm)                 # a rerun must not wipe the answer
            self.assertEqual(json.load(open(f))["ruleset"]["q1"]["answer"], "keep")
            out = os.path.join(t, "got.json")
            self.assertEqual(H.decisions_section("get", f, "ruleset", out), 0)
            self.assertEqual(json.load(open(out)), {"q1": {"answer": "keep"}})
            self.assertEqual(H.decisions_section("get", f, "settings", out), 1)
        finally:
            shutil.rmtree(t, ignore_errors=True)

    def test_group_versions(self):
        v = H.group_versions_of([{"id": "000", "group": []}, {"id": "001", "version": "Wazuh v5.0.0", "group": ["default", "pci"]},
                                 {"id": "002", "version": "Wazuh v4.14.10", "group": ["pci"]}])
        self.assertEqual(v, {"default": {"001": "Wazuh v5.0.0"}, "pci": {"001": "Wazuh v5.0.0", "002": "Wazuh v4.14.10"}})

    def test_stock_reference_generated_on_the_host_when_the_package_generator_is_there(self):
        sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        try:
            gen = os.path.join(sh.root, "var/ossec/packages_files/manager_installation_scripts/gen_ossec.sh")
            os.makedirs(os.path.dirname(gen))
            open(gen, "w").write('echo "<ossec_config><!-- generated for $3 $4 --></ossec_config>"\n')
            rc, out = sh.run('PKGFAM=rpm; settings_stock "$BUNDLE_DIR/stock"; cat "$BUNDLE_DIR/stock/ossec.conf"')   # OF1: the generator is the rpm path (deb: StockReferenceOnDebG5)
            self.assertIn("generated on this host", out)
            self.assertIn("<!-- generated for", out)
            os.unlink(gen)
            rc, out = sh.run('PKGFAM=rpm; settings_stock "$BUNDLE_DIR/stock"')
            self.assertIn("the shipped reference stock-4.14.10-", out)
            self.assertTrue(filecmp.cmp(os.path.join(sh.bundle, "stock/ossec.conf"), os.path.join(STOCK, "ossec.conf"), shallow=False))
        finally:
            sh.close()

class _FakeDashboard:
    """Saved objects as OpenSearch Dashboards keeps them: _find, _import (no overwrite: conflicts), GET, PUT (attributes
    merged, nested objects too), plus the history alias and the field list the dashboard step asks for."""

    def __init__(self):
        self.objs, self.calls = {}, []

    def http(self, method, url, user=None, password=None, token=None, body=None, headers=None, timeout=120):
        u = urllib.parse.urlparse(url)
        self.calls.append((method, u.path + ("?" + u.query if u.query else "")))
        if u.path.startswith("/_cat/aliases"):
            return 200, json.dumps([{"alias": "wazuh-findings-v5-legacy-4x", "index": "wazuh-legacy-4x-alerts-2026.11"}]).encode()
        if u.path == "/api/saved_objects/_find":
            return 200, json.dumps({"saved_objects": [dict(o, id=i[1], type=i[0]) for i, o in self.objs.items()]}).encode()
        if u.path == "/api/saved_objects/_import":
            payload = body.decode().split("\r\n\r\n", 1)[1].rsplit("\r\n--", 1)[0]
            over = "overwrite=true" in u.query
            errors = []
            for line in payload.splitlines():
                if line.strip():
                    o = json.loads(line)
                    k = (o["type"], o["id"])
                    if k in self.objs and not over:
                        errors.append({"id": o["id"], "error": {"type": "conflict"}})
                    else:
                        self.objs[k] = {"attributes": o["attributes"]}
            return 200, json.dumps({"success": not errors, "errors": errors}).encode()
        if u.path.startswith("/api/index_patterns/_fields_for_wildcard"):
            return 200, json.dumps({"fields": [{"name": "a"}]}).encode()
        m = re.match(r"^/api/saved_objects/([^/]+)/(.+)$", u.path)
        if m:
            k = (m.group(1), urllib.parse.unquote(m.group(2)))
            if k not in self.objs:
                return 404, b"{}"
            if method == "GET":
                return 200, json.dumps(self.objs[k]).encode()
            if method == "PUT":
                def merge(a, b):
                    for x, y in b.items():
                        if isinstance(y, dict) and isinstance(a.get(x), dict):
                            merge(a[x], y)
                        else:
                            a[x] = y
                merge(self.objs[k]["attributes"], json.loads(body)["attributes"] if isinstance(body, (bytes, str)) else body["attributes"])
                return 200, b"{}"
        return 404, b"{}"


NDJSON = [
    {"type": "index-pattern", "id": "wazuh-alerts-*", "attributes": {"title": "wazuh-alerts-*", "timeFieldName": "timestamp", "fields": "[]"}},
    {"type": "search", "id": "s1", "attributes": {"title": "high", "columns": ["rule.level"], "sort": [["timestamp", "desc"]],
                                                   "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "rule.level >= 10", "language": "kuery"}})}}},
]


class Rule20(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="rule20-")
        self.nd = os.path.join(self.t, "saved-objects.ndjson")
        open(self.nd, "w").write("\n".join(json.dumps(o) for o in NDJSON) + "\n")
        self.ledger = os.path.join(self.t, "saved-objects-ledger.json")

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def run_on(self, mod, dash, fn, *a):
        with mock.patch.object(mod, "http", dash.http), mock.patch.object(mod, "idx_password5", lambda: "x"):
            return quiet(getattr(mod, fn), *a)

    def test_rollback_resets_only_the_attributes_the_tool_changed(self):
        dash = _FakeDashboard()
        rc, out = self.run_on(H, dash, "import_saved_objects", self.nd)
        self.assertEqual(rc, 0, out)
        led = json.load(open(self.ledger))
        self.assertEqual(sorted(led["index-pattern/wazuh-alerts-*"]["attributes"]), ["timeFieldName", "title"])
        pat = dash.objs[("index-pattern", "wazuh-alerts-*")]["attributes"]
        pat["fieldFormatMap"] = json.dumps({"wazuh.rule.level": {"id": "string"}})       # the administrator's later edit (S5)
        n0 = len(dash.calls)
        rc, out = self.run_on(H, dash, "rollback_saved_objects", self.ledger)
        self.assertEqual(rc, 0, out)
        self.assertEqual(pat["title"], "wazuh-alerts-*")
        self.assertEqual(pat["timeFieldName"], "timestamp")
        self.assertIn("fieldFormatMap", pat)                                            # survives
        s1 = dash.objs[("search", "s1")]["attributes"]
        self.assertEqual(s1["columns"], ["rule.level"])
        self.assertIn('"rule.level >= 10"', s1["kibanaSavedObjectMeta"]["searchSourceJSON"])
        self.assertEqual({m for m, _ in dash.calls[n0:]}, {"GET", "PUT"})              # never a whole copy, never a delete

    def test_an_attribute_someone_changed_since_is_left(self):
        dash = _FakeDashboard()
        self.run_on(H, dash, "import_saved_objects", self.nd)
        dash.objs[("index-pattern", "wazuh-alerts-*")]["attributes"]["title"] = "admin-title"
        rc, out = self.run_on(H, dash, "rollback_saved_objects", self.ledger)
        self.assertEqual(dash.objs[("index-pattern", "wazuh-alerts-*")]["attributes"]["title"], "admin-title")
        self.assertIn("changed since the tool wrote it", out)

    def test_a_rerun_never_overwrites_an_existing_object(self):
        dash = _FakeDashboard()
        self.run_on(H, dash, "import_saved_objects", self.nd)
        pat = dash.objs[("index-pattern", "wazuh-alerts-*")]["attributes"]
        pat["fieldFormatMap"] = "admin"
        rc, out = self.run_on(H, dash, "import_saved_objects", self.nd)
        self.assertEqual(pat.get("fieldFormatMap"), "admin")
        self.assertIn("not overwritten", out)
        self.assertFalse(any("overwrite=true" in p for _, p in dash.calls))



if __name__ == "__main__":
    unittest.main()
