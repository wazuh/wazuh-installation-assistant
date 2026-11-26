"""Static checks over the merged tree: no name used but never bound in the Python stages (a merge that dropped a
definition), and every step of migrate.sh names a function that exists."""
import ast
import builtins
import os
import re
import unittest

import helpers

PY = ["mig_helper.py", "history_load.py", "apply_map.py", "loader_map.py", "identity_stage.py", "indexer_stage.py",
      "snap_consolidate.py", "snapshot_repo.py", "fleet-upgrade.py", "fleet-facts-4x.py", "dump.py", "load_unchanged.py",
      "cluster/node/node-state.py", "bundle_secrets.py", "settings_stage.py",
      "cluster/alertsjson-fold.py"]


def unbound(path):
    t = ast.parse(open(path).read())
    bound = set(dir(builtins)) | {"__file__", "__name__", "__doc__"}
    for n in ast.walk(t):
        if isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            bound.add(n.name)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            bound.add(n.id)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            bound.update((a.asname or a.name).split(".")[0] for a in n.names)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            bound.update(n.names)
    used = {n.id for n in ast.walk(t) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    return sorted(used - bound)


class Static(unittest.TestCase):
    def test_no_unbound_names_in_the_python_stages(self):
        bad = {f: unbound(os.path.join(helpers.SRC, f)) for f in PY}
        self.assertEqual({f: u for f, u in bad.items() if u}, {})

    def test_every_step_function_exists(self):
        txt = open(os.path.join(helpers.SRC, "migrate.sh")).read()
        defined = set(re.findall(r"^([a-z_0-9]+)\(\) *\{", txt, re.M))
        steps = re.findall(r"\bstep +[a-z_.]+ +\"[^\"]*\" +([a-z_0-9]+)", txt)
        self.assertGreater(len(steps), 40)
        self.assertEqual(sorted(set(steps) - defined), [])

    def test_every_phase_has_its_function(self):
        txt = open(os.path.join(helpers.SRC, "migrate.sh")).read()
        phases = re.search(r"^PHASES=\(([^)]*)\)", txt, re.M).group(1).split()
        for p in phases:
            self.assertRegex(txt, r"(?m)^phase_%s\(\) *\{" % p)


if __name__ == "__main__":
    unittest.main()
