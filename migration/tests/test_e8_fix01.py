"""E8-cluster-deb fix 01: the fingerprint check of the tool copied to each node must enter work_dir under sudo, because
the default work_dir (/root/wazuh-migration) is under /root, mode 700, and the SSH user may be a sudo user."""
import os, re, subprocess, tempfile, unittest
from helpers import SRC


def a_push_fp_line(src):
    body = open(os.path.join(src, "migrate-cluster.sh")).read()
    m = re.search(r"^a_push\(\).*?^  done; \}", body, re.S | re.M)
    return [l for l in m.group(0).splitlines() if "FP_CMD" in l and "rsh" in l][0]


class FingerprintCdUnderSudoE8Fix01(unittest.TestCase):
    def test_the_cd_runs_inside_sudo(self):
        line = a_push_fp_line(SRC)
        self.assertRegex(line, r'"\$SUDO sh -c \'cd \$\(q "\$MIG_HOME_N/src"\) && \$FP_CMD\'"')

    def test_a_user_without_access_to_the_directory_still_reads_the_fingerprint(self):
        # the command line built as a_push builds it, run by a shell standing in for the node, with "sudo" replaced by a
        # wrapper that enters the directory itself: the cd before sudo (the old form) runs in a directory the caller
        # cannot enter and prints nothing
        with tempfile.TemporaryDirectory() as t:
            d = os.path.join(t, "root", "wazuh-migration", "src"); os.makedirs(d)
            open(os.path.join(d, "a.sh"), "w").write("echo a\n")
            os.chmod(os.path.join(t, "root"), 0o000)
            try:
                fp = ('find . -type f ! -path "*/__pycache__/*" -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | '
                      'sed "s#  \\./#  src/#" | sha256sum | cut -c1-16')
                sudo = os.path.join(t, "fakesudo"); open(sudo, "w").write(
                    '#!/bin/sh\nchmod 700 "%s"; "$@"; rc=$?; chmod 000 "%s"; exit $rc\n' % (os.path.join(t, "root"), os.path.join(t, "root")))
                os.chmod(sudo, 0o755)
                new = "%s sh -c 'cd %s && %s'" % (sudo, d, fp)
                old = "cd %s && %s sh -c '%s'" % (d, sudo, fp)
                got_new = subprocess.run(["bash", "-c", new], capture_output=True, text=True).stdout.strip()
                got_old = subprocess.run(["bash", "-c", old], capture_output=True, text=True).stdout.strip()
            finally:
                os.chmod(os.path.join(t, "root"), 0o700)
            self.assertRegex(got_new, r"^[0-9a-f]{16}$")
            if os.geteuid() != 0:
                self.assertEqual(got_old, "")


if __name__ == "__main__":
    unittest.main()
