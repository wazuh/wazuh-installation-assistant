"""Shared helpers for the merged tool's unit tests (standard library only).

* load(path, name): import a Python file by path without writing bytecode anywhere.
* Shell: runs functions of a bash script (migrate.sh) in a sandbox: the script is copied up to its
  dispatcher into a temporary library, sourced with BUNDLE_DIR and the product paths pointed at temporary directories,
  and every system command it would call (systemctl, iptables, dpkg-query, curl...) is a stub on PATH that records its
  arguments and answers what the test tells it to.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap

sys.dont_write_bytecode = True
TOOL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.environ.get("MIG_TEST_SRC") or os.path.join(TOOL, "src")   # MIG_TEST_SRC: run the cases against another copy of src/


def load(path, name=None, extra_path=None):
    """Import a module from a file path, without bytecode; extra_path goes first on sys.path while it loads."""
    name = name or "m_%d" % abs(hash(path))
    saved = list(sys.path)
    if extra_path:
        sys.path.insert(0, extra_path)
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path[:] = saved


class Shell:
    """A sandbox for the functions of one bash script."""

    def __init__(self, script, stop_marker='if [ "$CMD" = __step ]; then'):
        self.tmp = tempfile.mkdtemp(prefix="migtest-")
        self.bin = os.path.join(self.tmp, "bin")
        self.calls = os.path.join(self.tmp, "calls.log")
        self.bundle = os.path.join(self.tmp, "bundle")
        self.root = os.path.join(self.tmp, "root")          # stands for / (V4, V5, V5ETC point under it)
        for d in (self.bin, self.bundle, self.root):
            os.makedirs(d)
        text = open(script).read()
        i = text.find(stop_marker)
        self.lib = os.path.join(self.tmp, "lib.sh")
        open(self.lib, "w").write(text[:i] if i > 0 else text)
        self.src_dir = os.path.dirname(os.path.abspath(script))
        open(self.calls, "w").close()

    def stub(self, name, body='exit 0'):
        """A command on PATH that logs '<name> <args>' to calls.log, then runs body (bash)."""
        p = os.path.join(self.bin, name)
        with open(p, "w") as f:
            f.write("#!/usr/bin/env bash\necho \"%s $*\" >> %s\n%s\n" % (name, self.calls, body))
        os.chmod(p, 0o755)

    def run(self, code, env=None, timeout=60):
        """Source the library, re-point the product paths, run `code`. Returns (rc, output)."""
        prelude = textwrap.dedent('''
            HERE=%(src)s; HELPER=$HERE/mig_helper.py; SELF=$HERE/migrate.sh
            V4=%(root)s/var/ossec; V5=%(root)s/var/wazuh-manager; V5ETC=%(root)s/etc/wazuh-manager
            mkdir -p "$STATE" "$LOGS" "$RESULTS" "$WORK_DIR" "$V4/etc" "$V5/bin" "$V5ETC"
        ''') % {"src": self.src_dir, "root": self.root}
        full = "set +e\nsource %s\nset +e +u\n%s\n%s\n" % (self.lib, prelude, code)
        e = dict(os.environ)
        e.update({"PATH": self.bin + ":" + os.environ["PATH"], "BUNDLE_DIR": self.bundle,
                  "WORK_DIR": os.path.join(self.tmp, "work"), "PYTHONDONTWRITEBYTECODE": "1",
                  "MIG_GUARD_DROPIN_DIR": os.path.join(self.tmp, "dropin"), "MIG_GUARD_COPY": os.path.join(self.tmp, "guard-copy.sh")})
        e.update(env or {})
        p = subprocess.run(["bash", "-c", full], env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.decode(errors="replace")

    def called(self):
        return open(self.calls).read().splitlines()

    def write(self, rel, content, base=None):
        p = os.path.join(base or self.bundle, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content if isinstance(content, str) else json.dumps(content))
        return p

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
