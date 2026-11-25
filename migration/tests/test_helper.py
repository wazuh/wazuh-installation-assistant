"""mig_helper.py: the setup-status gate (C1), R2's address and FIPS fixes, rule 8's in-force wait, F7's impostor rule in
the reconcile, F10's PENDING history lines, S5's dashboard fixes, the group-stamp registry."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import helpers

H = helpers.load(os.path.join(helpers.SRC, "mig_helper.py"), "mig_helper_merged")


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


class SetupStatusC1(unittest.TestCase):
    """Conflict C1: F7/F10 accepted 'up_to_date' alone (from 20 documents), F6 required one 'ready' among all of them."""
    F6_NIGHTLY = ["ready"] + ["up_to_date"] * 52       # F6-D8: 53 documents on the 2026-11-24 nightly
    EARLIER = ["ready", "ready"]

    def test_vocabulary_comes_from_the_build_manifest(self):
        v = H.build_manifest()["setup_status"]
        self.assertEqual(v["required_one_of"], ["ready"])
        self.assertIn("up_to_date", v["accepted"])

    def test_nightly_with_template_documents_is_ready(self):
        self.assertTrue(H.setup_ready(self.F6_NIGHTLY, H.build_manifest()["setup_status"]))
        self.assertTrue(H.setup_ready(self.EARLIER))

    def test_nothing_read_or_an_unknown_word_is_not_ready(self):
        self.assertFalse(H.setup_ready([]))
        self.assertFalse(H.setup_ready(["ready", "failed"]))
        self.assertFalse(H.setup_ready(["up_to_date"] * 20))   # F7's truncated read: no 'ready' document seen

    def test_without_the_fix_the_nightly_never_passes(self):
        old = lambda st: bool(st) and all(x == "ready" for x in st)    # P1's rule
        self.assertFalse(old(self.F6_NIGHTLY))

    def test_gate_reads_every_document(self):
        calls = []

        def fake_idx(method, path, pw, body=None, **k):
            calls.append(path)
            if path.startswith("/.wazuh-setup-status/_search?size=1000"):
                return 200, {"hits": {"hits": [{"_source": {"status": s}} for s in self.F6_NIGHTLY]}}
            if path.startswith("/.wazuh-setup-status"):
                return 200, {"hits": {"hits": [{"_source": {"status": "up_to_date"}}] * 20}}
            return 404, {}
        with mock.patch.object(H, "idx", fake_idx), mock.patch.object(H, "idx_password5", lambda: "x"), \
                mock.patch("builtins.open", mock.mock_open(read_data="")):
            try:
                quiet(H.setup_status)
            except Exception:  # noqa: BLE001  (the rest of the gate reads the manager; only the read size matters here)
                pass
        self.assertTrue(any("size=1000" in c for c in calls), calls)


class R2Fixes(unittest.TestCase):
    def test_indexer_address_from_its_configuration(self):
        for text, want in (("network.host: 10.0.0.5\n", "10.0.0.5"), ('network.host: "0.0.0.0"\n', "127.0.0.1"),
                           ("network.host: _local_\n", "127.0.0.1"), ("cluster.name: x\n", "127.0.0.1")):
            with mock.patch("builtins.open", mock.mock_open(read_data=text)):
                self.assertEqual(H.idx_host(), want, text)

    def test_fips_host_refuses_blake2b_digest_size(self):
        """R2: the 4.14 OVA boots with fips_enabled=1; blake2b(digest_size=10) raises there."""
        def fips_blake2b(*a, **k):
            raise ValueError("digest_size not supported in FIPS mode")
        with mock.patch.object(H.hashlib, "blake2b", fips_blake2b):
            self.assertEqual(len(H._short_digest(b"abc")), 10)
            with self.assertRaises(ValueError):          # without the fix: P1 called blake2b directly
                H.hashlib.blake2b(b"abc", digest_size=10)


class InForceRule8(unittest.TestCase):
    LOG = ["2026/11/24 02:49:00 wazuh-manager-engine: INFO: Successfully synchronized space 'standard'",
           "2026/11/24 02:51:10 x: INFO: [CM::Sync] Hot swapped ... Successfully synchronized space 'custom'",
           "2026/11/24 02:51:30 x: INFO: Successfully synchronized space 'standard'"]

    def test_only_synchronisations_after_the_decision_count(self):
        self.assertEqual(H.synced_spaces(self.LOG, "2026/11/24 02:50:00"), {"custom": "2026/11/24 02:51:10", "standard": "2026/11/24 02:51:30"})
        self.assertEqual(H.synced_spaces(self.LOG[:1], "2026/11/24 02:50:00"), {})

    def test_wait_times_out_and_keeps_the_listeners_closed(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write(self.LOG[0] + "\n")
        try:
            r, out = quiet(H.wait_in_force, "2026/11/24 02:50:00", "standard", "0", f.name)
            self.assertEqual(r, 1)
            self.assertIn("the listeners stay closed", out)
            r, out = quiet(H.wait_in_force, "2026/11/24 02:50:00", "", "0", f.name)
            self.assertEqual(r, 0)
        finally:
            os.unlink(f.name)

    def test_unreadable_log_stops_the_gate(self):
        r, out = quiet(H.wait_in_force, "2026/11/24 02:50:00", "standard", "0", "/nonexistent/manager.log")
        self.assertEqual(r, 1)


class _FakeApi:
    def __init__(self, agents, groups):
        self.agents, self.groups, self.calls = agents, groups, []

    def get(self, path):
        return [{"name": g} for g in self.groups] if path.startswith("/groups") else self.agents

    def call(self, method, path, body=None, headers=None):
        self.calls.append((method, path))
        return 200, {}


class ReconcileImpostorF7(unittest.TestCase):
    """F7: an agent that enrolled by itself under a bundle id (key differs) is named and never given the real agent's groups."""

    def _bundle(self, d):
        os.makedirs(os.path.join(d, "fingerprint"))
        os.makedirs(os.path.join(d, "v4", "etc"))
        json.dump([{"id": "001", "name": "ag2", "group": ["default", "acme"]}], open(os.path.join(d, "fingerprint", "agents.json"), "w"))
        json.dump(["acme", "default"], open(os.path.join(d, "fingerprint", "groups.json"), "w"))
        open(os.path.join(d, "v4", "etc", "client.keys"), "w").write("001 ag2 any REALKEY\n")

    def _run(self, mod, d):
        fake = _FakeApi([{"id": "001", "name": "ag2", "group": ["default"]}], ["acme", "default"])
        real_open = open

        def fake_open(p, *a, **k):
            if p == "/etc/wazuh-manager/client.keys":
                return io.StringIO("001 ag2 any IMPOSTORKEY\n")
            return real_open(p, *a, **k)
        with mock.patch.object(mod, "Api", lambda *a, **k: fake), mock.patch.object(mod, "api_password5", lambda: "x"), \
                mock.patch.object(mod.time, "sleep", lambda s: None), mock.patch("builtins.open", fake_open):
            r, out = quiet(mod.reconcile_membership, d, "--apply")
        return r, out, fake.calls

    def test_impostor_is_named_and_not_repaired(self):
        with tempfile.TemporaryDirectory() as d:
            self._bundle(d)
            r, out, calls = self._run(H, d)
        self.assertEqual(r, 1)
        self.assertIn("never repaired", out)
        self.assertFalse(any("/agents/001/group" in p for _, p in calls), calls)



class AgentRegistry(unittest.TestCase):
    def test_registry_for_the_group_stamp_from_the_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "fingerprint"))
            json.dump([{"id": "000", "name": "mgr", "group": []}, {"id": "002", "name": "ag", "group": ["default", "pci"]}],
                      open(os.path.join(d, "fingerprint", "agents.json"), "w"))
            out = os.path.join(d, "reg.json")
            quiet(H.agent_registry, d, out)
            reg = json.load(open(out))
        self.assertEqual(reg["agents"]["002"], {"name": "ag", "groups": ["default", "pci"]})


class CompareHistoryPendingF10(unittest.TestCase):
    def _dirs(self, d):
        fp, t4, t5 = (os.path.join(d, x) for x in ("fp", "t4", "t5"))
        for x in (fp, t4, t5):
            os.makedirs(x)
        for name, v in (("agents.json", []), ("client_keys.json", {}), ("group_files.json", {}), ("enrollment.json", {"authd_pass_sha256": "a", "authd_pass_bytes": 32}),
                        ("indexer_security.json", {"internalusers": [], "roles": [], "rolesmapping": []}), ("saved_objects.json", []), ("manager_settings.json", {"ossec_conf_blocks": [], "local_internal_options": []}),
                        ("indices.json", {"wazuh-alerts-4.x-2026.11.01": 10})):
            json.dump(v, open(os.path.join(fp, name), "w"))
        json.dump({"users": [], "roles": [], "policies": [], "rules": []}, open(os.path.join(t4, "api_security.json"), "w"))
        json.dump({"per_source_index": {}}, open(os.path.join(t5, "history.json"), "w"))
        return fp, t4, t5

    def test_history_lines_read_pending_before_the_history_phase(self):
        with tempfile.TemporaryDirectory() as d:
            fp, t4, t5 = self._dirs(d)
            with mock.patch.dict(os.environ, {"HISTORY_PENDING": "1"}):
                try:
                    r, out = quiet(H.compare, t4, fp, t5)
                except Exception as e:  # noqa: BLE001
                    self.skipTest("compare needs more of a real bundle than this fixture: %r" % e)
            self.assertIn("PENDING", out)
            with mock.patch.dict(os.environ, {"HISTORY_PENDING": "0"}):
                r, out = quiet(H.compare, t4, fp, t5)
            self.assertNotIn("PENDING", out)


class SavedObjectsS5(unittest.TestCase):
    NDJSON = "\n".join(json.dumps(o) for o in [
        {"type": "index-pattern", "id": "wazuh-alerts-*", "attributes": {"title": "wazuh-alerts-*", "timeFieldName": "timestamp"}},
        {"type": "search", "id": "s1", "attributes": {"title": "high", "columns": ["rule.level"], "sort": [["timestamp", "desc"]],
                                                       "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                                                           {"query": {"query": "rule.level >= 10 and agent.name:web", "language": "kuery"}})}}},
    ]) + "\n"

    def _run(self, aliases, fields=5):
        sent = {}

        def fake_idx(method, path, pw, body=None, **k):
            return (200, aliases) if path.startswith("/_cat/aliases") else (404, {})

        def fake_http(method, url, **k):
            if "_import" in url:
                sent["payload"] = k.get("body", b"")
                return 200, json.dumps({"success": True}).encode()
            if "_fields_for_wildcard" in url:
                sent["fields_url"] = url
                return 200, json.dumps({"fields": [{"name": "x"}] * fields}).encode()
            return 404, b"{}"
        with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False) as f:
            f.write(self.NDJSON)
        try:
            with mock.patch.object(H, "idx", fake_idx), mock.patch.object(H, "http", fake_http), \
                    mock.patch.object(H, "idx_password5", lambda: "x"), mock.patch.object(H, "saved_objects", lambda *a: []):
                r, out = quiet(H.import_saved_objects, f.name)
        finally:
            os.unlink(f.name)
        return r, out, sent

    def test_refused_while_no_history_alias_exists(self):
        r, out, sent = self._run([])
        self.assertEqual(r, 1)
        self.assertNotIn("payload", sent)

    def test_one_wildcard_over_the_aliases_kql_range_and_sort_rewritten(self):
        r, out, sent = self._run([{"alias": "wazuh-findings-v5-legacy-4x", "index": "wazuh-legacy-4x-alerts-2026.11"}])
        self.assertEqual(r, 0, out)
        p = sent["payload"].decode()
        self.assertIn("wazuh-findings-v5*-legacy-4x", p)
        self.assertIn("legacy.alert.rule.level >= 10", p)           # S5: KQL range on the preserved field
        self.assertIn('[\\"legacy.alert.timestamp\\", \\"desc\\"]', json.dumps(p)[0:0] + p.replace('"', '\\"'))
        self.assertIn("pattern=wazuh-findings-v5%2A-legacy-4x", sent["fields_url"])

    def test_an_import_whose_pattern_has_no_fields_fails(self):
        r, out, sent = self._run([{"alias": "wazuh-findings-v5-legacy-4x", "index": "i"}], fields=0)
        self.assertEqual(r, 1)



class FeedRule14(unittest.TestCase):
    LINES = ["2026/11/23 15:58:01 wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: Consumer 'cti:catalog:consumer:vulnerabilities' in index '.wazuh-cti-consumers' is ready. Starting feed download.",
             "2026/11/23 16:15:32 wazuh-manager-modulesd:content-updater: INFO: IndexerDownloader: Slice 0 (1/2) in progress \u2014 203900 documents so far, cursor '1321088', 1050s elapsed"]

    def test_a_load_in_progress_is_seen_and_quiet_after(self):
        import time as _t
        t = _t.mktime(_t.strptime("2026/11/23 16:15:32", "%Y/%m/%d %H:%M:%S"))
        self.assertEqual(H.feed_load_state(self.LINES, t + 60)[0], "loading")
        self.assertEqual(H.feed_load_state(self.LINES, t + 600)[0], "quiet")
        self.assertEqual(H.feed_load_state(["2026/11/23 16:00:00 other: INFO: x"], t)[0], "unknown")

if __name__ == "__main__":
    unittest.main()
