"""E9-aio fix 01: on a first attempt (no <bundle>.attempt-* folder) the ruleset import step ended with exit 2 and no
message right after "rmig apply exit 0": the alerts list ran ls on a pattern that matches nothing, and under
pipefail and errexit (the step body's own shell) its exit 2 ended the step. Every first attempt with custom rules
failed in the outage, and running again failed the same way."""
import os
import unittest

import helpers

SRC = helpers.SRC


class FirstAttemptRulesetVerifyE9(unittest.TestCase):
    def setUp(self):
        self.sh = helpers.Shell(os.path.join(SRC, "migrate.sh"))
        self.addCleanup(self.sh.close)

    def run_step(self):
        # as step() runs a body: a fresh shell with errexit and pipefail
        code = ('rmig() { echo "RMIG $*"; }; rmig_dialect_installed() { echo 5.0; }; '
                'set -Eeuo pipefail; trap - ERR; im_ruleset; echo STEP-END')
        return self.sh.run(code)

    def test_first_attempt_reaches_the_verification(self):
        self.sh.write("v4/alerts/alerts.json", "{}")
        self.sh.write("work/ruleset-migration/ENGINE_HELPERS", "5.0\n")
        self.assertFalse([p for p in os.listdir(os.path.dirname(self.sh.bundle))
                          if p.startswith(os.path.basename(self.sh.bundle) + ".attempt-")])
        rc, out = self.run_step()
        self.assertEqual(rc, 0, out)
        self.assertIn("STEP-END", out)
        line = [l for l in out.splitlines() if l.startswith("RMIG verify")][0]
        self.assertIn(os.path.join(self.sh.bundle, "v4", "alerts", "alerts.json"), line)
        self.assertNotIn("earlier attempts", out)

    def test_a_later_attempt_still_reads_the_earlier_alerts(self):
        self.sh.write("v4/alerts/alerts.json", "{}")
        self.sh.write("v4/alerts/x.json", "{}", base=self.sh.bundle + ".attempt-1")
        self.sh.write("work/ruleset-migration/ENGINE_HELPERS", "5.0\n")
        rc, out = self.run_step()
        self.assertEqual(rc, 0, out)
        line = [l for l in out.splitlines() if l.startswith("RMIG verify")][0]
        self.assertIn(os.path.join(self.sh.bundle + ".attempt-1", "v4", "alerts", "x.json"), line)


if __name__ == "__main__":
    unittest.main()
