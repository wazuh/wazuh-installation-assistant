"""The shipped field map is the compact form of the evidence map (tool/map-evidence/, not shipped): the converted
documents, the field-hiding map and the indexer stage's maps must be the same with either."""
import gzip
import json
import os
import sys
import types
import unittest

import helpers

SRC = helpers.SRC
EVIDENCE = os.path.join(os.path.dirname(SRC), "map-evidence")
FULL = os.path.join(EVIDENCE, "history-loader-map.full.json")
SHIPPED = os.path.join(SRC, "history-loader-map.json")
# the alert corpus of the field-map work, when it is on this machine (100,006 alerts); else the built-in sample below
CORPUS = os.environ.get("MAP_CORPUS", os.path.join(os.path.dirname(os.path.dirname(SRC)), "fixture", "truth", "docs.ndjson.gz"))
SAMPLE = [
    {"timestamp": "2026-11-20T10:00:00.000+0000", "rule": {"id": "61603", "level": 3, "groups": ["windows", "windows_security"]},
     "decoder": {"name": "windows_eventchannel"}, "agent": {"id": "001", "name": "win-1"}, "full_log": "x",
     "data": {"win": {"system": {"eventID": "4688", "channel": "Security"}, "eventdata": {"image": "C:\\\\Windows\\\\cmd.exe"}}}},
    {"timestamp": "2026-11-20T10:00:01.000+0000", "rule": {"id": "5715", "level": 3, "groups": ["sshd", "authentication_success"]},
     "decoder": {"name": "sshd"}, "agent": {"id": "002", "name": "lin-1"}, "data": {"srcip": "10.0.0.9", "dstuser": "root"},
     "full_log": "Accepted publickey for root from 10.0.0.9"},
    {"timestamp": "2026-11-20T10:00:02.000+0000", "rule": {"id": "550", "level": 7, "groups": ["ossec", "syscheck"]},
     "syscheck": {"event": "modified", "path": "/etc/passwd"}, "agent": {"id": "000", "name": "manager"}},
]


@unittest.skipUnless(os.path.exists(FULL), "the evidence map is not beside the tool (an exported tree)")
class CompactMapIsTheFullMapsBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, EVIDENCE)
        import compact_map
        cls.CM = compact_map
        cls.full = json.load(open(FULL))
        cls.shipped = json.load(open(SHIPPED))
        cls.LM = helpers.load(os.path.join(SRC, "loader_map.py"), "loader_map_compact", extra_path=SRC)

    def test_the_shipped_map_is_the_compact_form_of_the_evidence_map(self):
        self.assertEqual(self.shipped, self.CM.compact(self.full))
        self.assertEqual(open(SHIPPED).read(), self.CM.dump(self.CM.compact(self.full)))

    def test_no_evidence_key_is_shipped(self):
        for r in self.shipped["rules"]:
            self.assertFalse(set(r) & self.CM.RULE_DROP, r["id"])
        for f, s in self.shipped["target_schema"].items():
            self.assertLessEqual(set(s), {"type", "ignore_above"}, f)
        self.assertNotIn("/home/", open(SHIPPED).read())

    def test_field_hiding_and_indexer_maps_are_the_same(self):
        self.assertEqual(self.LM.field_hiding_map(self.full), self.LM.field_hiding_map(self.shipped))
        IS = helpers.load(os.path.join(SRC, "indexer_stage.py"), "indexer_stage_compact", extra_path=SRC)
        a = IS.load_maps(types.SimpleNamespace(field_map="", history_map=FULL))
        b = IS.load_maps(types.SimpleNamespace(field_map="", history_map=SHIPPED))
        self.assertEqual(a, b)

    def corpus(self):
        if os.path.exists(CORPUS):
            with gzip.open(CORPUS, "rt") as f:
                for line in f:
                    if line.strip():
                        d = json.loads(line)
                        yield d.get("_source", d)
        else:
            yield from SAMPLE

    def test_converted_documents_are_byte_identical(self):
        reg = {"001": {"name": "win-1", "groups": ["g1"]}, "002": {"name": "lin-1", "groups": ["g2"]}}
        a = self.LM.LoaderMapper("wazuh", True, reg, spec=self.full)
        b = self.LM.LoaderMapper("wazuh", True, reg, spec=self.shipped)
        self.assertEqual(a.targets(), b.targets())
        n = 0
        for alert in self.corpus():
            x = json.dumps(a.convert(json.loads(json.dumps(alert)), "i", "1"), sort_keys=True, ensure_ascii=False)
            y = json.dumps(b.convert(json.loads(json.dumps(alert)), "i", "1"), sort_keys=True, ensure_ascii=False)
            self.assertEqual(x, y, alert.get("id"))
            n += 1
        self.assertGreater(n, 0)
        print("compact map: %d alert(s) converted identically (%s)" % (n, CORPUS if os.path.exists(CORPUS) else "built-in sample"))


if __name__ == "__main__":
    unittest.main()
