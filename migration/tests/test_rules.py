"""The static rule check (rules 1 to 23 -> file and line) and the absence checks it relies on."""
import os
import re
import unittest

import helpers
import rule_table


class RuleTable(unittest.TestCase):
    def test_every_rule_is_anchored_in_the_code(self):
        rows, missing = rule_table.build()
        rule_table.write(rows, missing)
        self.assertEqual(sorted(n for n, _, _, _ in rows), list(range(1, 24)))
        self.assertEqual(missing, [])

    def test_the_tool_never_sets_do_not_fail_on_forbidden(self):
        """Rule 9: it would silently hide the history cluster-wide."""
        for r, _, fs in os.walk(helpers.SRC):
            for f in fs:
                if f.endswith((".py", ".sh")):
                    t = open(os.path.join(r, f), errors="replace").read()
                    for m in re.finditer(r"do_not_fail_on_forbidden[\"']?\s*[:=]\s*[\"']?true", t, re.I):
                        self.fail("%s sets do_not_fail_on_forbidden" % f)


if __name__ == "__main__":
    unittest.main()
