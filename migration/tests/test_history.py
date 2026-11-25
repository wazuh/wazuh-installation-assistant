"""History stage: H5's journal and fail-closed reads, the date fix (conflict C4: H5 and S5), S5's `on` (conflict C5: no
bypass), the field-hiding map generated from the loader (C8), the snapshot rules (H6) and the snapshot transport's
refusal while the shaping pipeline is empty (C7)."""
import contextlib
import datetime as real_dt
import io
import json
import os
import re
import tempfile
import time
import types
import unittest
from unittest import mock

import helpers

SRC = helpers.SRC
HL = helpers.load(os.path.join(SRC, "history_load.py"), "history_load", extra_path=SRC)
AM = helpers.load(os.path.join(SRC, "apply_map.py"), "apply_map_merged", extra_path=SRC)
LM = helpers.load(os.path.join(SRC, "loader_map.py"), "loader_map_merged", extra_path=SRC)


def quiet(fn, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


class _Py39Datetime(real_dt.datetime):
    """datetime as Python 3.9 parses ISO strings: offsets only as +HH:MM, fractions of exactly 3 or 6 digits."""

    @classmethod
    def fromisoformat(cls, s):
        if re.search(r"[+-]\d{4}$", s) or re.search(r"\.(\d+)", s) and len(re.search(r"\.(\d+)", s).group(1)) not in (3, 6):
            raise ValueError("Invalid isoformat string: %r" % s)
        return real_dt.datetime.fromisoformat(s)


PY39 = types.SimpleNamespace(datetime=_Py39Datetime, timezone=real_dt.timezone, timedelta=real_dt.timedelta)
DATES = ["2026-11-24T10:00:00.123+0000",          # every 4.x `timestamp`
         "2026-11-24T10:00:00.1234567Z",          # cloud logs: 7 digits
         "2026-11-24T10:00:00.123456789+00:00"]   # 9 digits


class DateFixC4(unittest.TestCase):
    def test_merged_keeps_every_date_on_python39_and_writes_the_original(self):
        with mock.patch.object(AM, "dt", PY39):
            for d in DATES:
                self.assertEqual(AM.date_norm(d), d, d)
                self.assertTrue(AM.date_ok(d))
            self.assertIsNone(AM.date_norm("not a date"))




class OnCannotBeBypassedC5(unittest.TestCase):
    def _a(self, **k):
        return types.SimpleNamespace(accept_role_loss=False, remove_bundle=False, state_dir=None, **k)

    def test_on_refuses_when_a_role_would_lose_every_module(self):
        with mock.patch.object(HL, "cmd_prove", lambda *x: 0), mock.patch.object(HL, "cmd_audit_roles", lambda *x: 1), \
                mock.patch.object(HL, "alias_actions", lambda *x: self.fail("aliases touched")):
            with self.assertRaises(SystemExit):
                HL.cmd_on(None, self._a(), None)

    def test_on_always_proves_and_the_lab_switch_is_gone(self):
        with mock.patch.object(HL, "cmd_prove", lambda *x: 1):
            with self.assertRaises(SystemExit):
                HL.cmd_on(None, self._a(unproven=True), None)
        self.assertNotIn('add_argument("--unproven"', open(os.path.join(SRC, "history_load.py")).read())
        self.assertNotIn('"--unproven"', open(os.path.join(SRC, "snap_consolidate.py")).read())



class FailClosedReadsH5(unittest.TestCase):
    def test_a_refused_count_stops_instead_of_reading_minus_one(self):
        with self.assertRaises(SystemExit):
            HL.count(lambda *a: (403, {"error": "no permissions"}), "x")

    def test_a_refused_listing_stops_instead_of_reading_nothing(self):
        with self.assertRaises(SystemExit):
            HL.existing_targets(lambda *a: (403, {}))


class RetentionJournalH5(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        day = 86400000
        now = time.time() * 1000
        self.now = now
        self.b = types.SimpleNamespace(months={"2025.01": {"srcs": ["wazuh-alerts-4.x-2025.01.31"], "docs": 5, "cd": now - 400 * day},
                                               "2026.11": {"srcs": ["wazuh-alerts-4.x-2026.11.20"], "docs": 7, "cd": now - 4 * day}})
        self.a = types.SimpleNamespace(retention="365d", load_expired=False)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def _api(self, present):
        return lambda m, p, *x, **k: (200, [{"index": i, "docs.count": "1", "status": "open"} for i in present])

    def test_a_month_past_the_retention_is_not_loaded(self):
        j = HL.Journal(os.path.join(self.d, "journal.json"))
        (load, expired, loaded), _ = quiet(HL.classify_months, self._api([]), self.a, self.b, j, self.now)
        self.assertEqual((load, expired), (["2026.11"], ["2025.01"]))

    def test_a_loaded_month_the_retention_deleted_is_never_recreated(self):
        j = HL.Journal(os.path.join(self.d, "journal.json"))
        j.month("2025.01").update({"status": "loaded", "expires_ms": self.now - 1, "targets": {"wazuh-legacy-4x-alerts-2025.01": {"x": 5}}})
        (load, expired, loaded), out = quiet(HL.classify_months, self._api([]), self.a, self.b, j, self.now)
        self.assertNotIn("2025.01", load)
        self.assertIn("2025.01", loaded)
        self.assertIn("wazuh-legacy-4x-alerts-2025.01", j.month("2025.01")["deleted_by_retention"])

    def test_a_loaded_month_missing_before_its_date_stops_the_run(self):
        j = HL.Journal(os.path.join(self.d, "journal.json"))
        j.month("2026.11").update({"status": "loaded", "expires_ms": self.now + 10 ** 9, "targets": {"wazuh-legacy-4x-alerts-2026.11": {"x": 7}}})
        with self.assertRaises(SystemExit):
            quiet(HL.classify_months, self._api([]), self.a, self.b, j, self.now)


class FieldHidingMapC8(unittest.TestCase):
    def test_generated_from_the_rules_the_loader_evaluates(self):
        g = LM.field_hiding_map()
        self.assertIn("user.target.name", g["data.dstuser"])       # S5-D1: the field the hand-made map missed
        self.assertIn("message", g["full_log"])
        self.assertIn("wazuh.agent.id", g["agent.id"])

    def test_indexer_stage_hides_the_union(self):
        IS = helpers.load(os.path.join(SRC, "indexer_stage.py"), "indexer_stage", extra_path=SRC)
        a = types.SimpleNamespace(field_map="", history_map=os.path.join(SRC, "history-loader-map.json"))
        filt, hide = IS.load_maps(a)
        self.assertIn("user.target.name", hide["data.dstuser"])
        self.assertEqual(filt.get("agent.id"), "wazuh.agent.id")
        spec = json.load(open(os.path.join(SRC, "history-loader-map.json")))
        for f, tg in spec["map"].items():                            # never fewer fields than the map builder's index
            self.assertTrue(set(tg) <= set(hide.get(f, [])), f)



class SnapshotRulesH6(unittest.TestCase):
    SR = helpers.load(os.path.join(SRC, "snapshot_repo.py"), "snapshot_repo")

    def test_repository_locations(self):
        for p in ("/var/lib/wazuh-indexer/backup", "/tmp/repo", "/root/repo", "/etc/repo", "/var/ossec/backup", "relative"):
            self.assertFalse(self.SR.check_path(p)[0], p)
        for p in (self.SR.DEFAULT_REPO, "/srv/repo", "/opt/x", "/var/backups/r"):
            self.assertTrue(self.SR.check_path(p)[0], p)

    def test_path_repo_line_rewritten_as_a_list_never_added(self):
        y = "cluster.name: x\npath.repo: /var/lib/wazuh-indexer/backup\n"
        out = self.SR.path_repo_rewrite(y, "/var/lib/wazuh-migration/repo")
        self.assertEqual(len(re.findall(r"^path\.repo", out, re.M)), 1)
        self.assertIn('["/var/lib/wazuh-indexer/backup", "/var/lib/wazuh-migration/repo"]', out)
        self.assertEqual(out, self.SR.path_repo_rewrite(out, "/var/lib/wazuh-migration/repo"))
        with self.assertRaises(ValueError):
            self.SR.path_repo_rewrite(y + "path.repo: /x\n", "/y")

    def test_restore_body(self):
        b = self.SR.restore_body("wazuh-alerts-4.x-2026.11.*")
        self.assertIs(b["include_global_state"], False)
        with self.assertRaises(ValueError):
            self.SR.restore_body("wazuh-findings-v5-x")


class SnapshotTransportC7(unittest.TestCase):
    def test_consolidate_refuses_an_unsafe_repository_first(self):
        """OF1 (decision 9): the C7 refusal of an empty pipeline is gone (restored copies go through the Python loader,
        test_of1.SnapshotThroughThePythonLoaderDecision9); the repository rule (H6) still refuses before anything."""
        SC = helpers.load(os.path.join(SRC, "snap_consolidate.py"), "snap_consolidate", extra_path=SRC)
        a = types.SimpleNamespace(repo_path="/var/lib/wazuh-indexer/backup/sc1", meta="/nonexistent")
        with self.assertRaises(SystemExit) as e:
            SC.cmd_consolidate(None, a)
        self.assertIn("REFUSED repository", str(e.exception))


class Python38(unittest.TestCase):
    def test_every_python_file_parses_with_the_38_grammar(self):
        import ast
        bad = []
        for r, _, fs in os.walk(SRC):
            for f in fs:
                if f.endswith(".py"):
                    p = os.path.join(r, f)
                    try:
                        t = ast.parse(open(p).read(), feature_version=(3, 8))
                    except SyntaxError as e:
                        bad.append("%s: %s" % (p, e))
                        continue
                    for n in ast.walk(t):   # 3.9+ library calls the grammar check does not see
                        if isinstance(n, ast.Attribute) and n.attr in ("removeprefix", "removesuffix", "is_relative_to"):
                            bad.append("%s:%d uses %s (3.9+)" % (p, n.lineno, n.attr))
                        anns = []
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            anns = [x.annotation for x in n.args.args + n.args.kwonlyargs if x.annotation] + ([n.returns] if n.returns else [])
                        elif isinstance(n, ast.AnnAssign):
                            anns = [n.annotation]
                        for an in anns:     # evaluated at definition time on 3.8: list[str] and X | Y raise there
                            for m in ast.walk(an):
                                if (isinstance(m, ast.Subscript) and isinstance(m.value, ast.Name) and m.value.id in ("list", "dict", "set", "tuple", "type")) \
                                        or (isinstance(m, ast.BinOp) and isinstance(m.op, ast.BitOr)):
                                    bad.append("%s:%d annotation needs 3.9+/3.10+" % (p, n.lineno))
        self.assertEqual(bad, [])


class Manifest(unittest.TestCase):
    def test_map_checksum_recorded_equals_the_shipped_map(self):
        import hashlib
        m = json.load(open(os.path.join(SRC, "manifest", "builds.json")))
        self.assertEqual(m["field_map"]["sha256"], hashlib.sha256(open(os.path.join(SRC, "history-loader-map.json"), "rb").read()).hexdigest())
        self.assertEqual(LM.MAP_SHA256, m["field_map"]["sha256"])


if __name__ == "__main__":
    unittest.main()
