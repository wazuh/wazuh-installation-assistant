# Unit Tests — Wazuh Installation Assistant

Unit tests for the bash scripts in this repository. Tests are written in **Python pytest** and run bash functions directly via `subprocess`, with mock injection to avoid real system calls. No Docker required.

## Structure

```
tests/unit/
├── conftest.py                  # Shared helpers: run_bash_function, assert_success, assert_failure
├── test_checks.py               # checks.sh — argument validation, arch, health, cert checks
├── test_common.py               # common.sh — system detection, package manager checks
├── test_cert_functions.py       # certFunctions.sh — cert generation, OpenSSL checks, config parsing
├── test_passwords_functions.py  # passwordsFunctions.sh — password read/change, component checks
├── test_install_common.py       # installCommon.sh — config retrieval, prerequisites, service start
├── test_manager.py              # manager.sh — install (apt/yum), cluster start
├── test_indexer.py              # indexer.sh — install (apt/yum), initialize, service start
├── test_dashboard.py            # dashboard.sh — install (apt/yum), configure, initialize
└── legacy/                      # Preserved Bach/Docker tests (not executed, kept as reference)
```

## Requirements

- Python >= 3.10
- [Hatch](https://hatch.pypa.io/) (`pip install hatch`)
- `bash` available on the host (standard on Linux/macOS)

## Running the tests

### With Hatch (recommended — mirrors CI)

```bash
# Run all unit tests with coverage report
hatch run dev:test-cov

# Run without coverage (faster)
hatch run dev:test
```

### With pytest directly

```bash
# From the repository root
pip install pytest pytest-cov
pytest tests/unit/ -v

# With coverage
pytest tests/unit/ --cov=. --cov-report=term-missing

# Run a single test file
pytest tests/unit/test_checks.py -v

# Run a single test class or method
pytest tests/unit/test_checks.py::TestChecksArch -v
pytest tests/unit/test_checks.py::TestChecksArch::test_fail_unsupported_arch -v
```

### Filtering by keyword

```bash
# Run all tests whose name contains "apt"
pytest tests/unit/ -k "apt"

# Run all failure tests
pytest tests/unit/ -k "fail"
```

## How tests work

Each test sources the real bash script under test plus its dependencies, then calls the target function inside a `bash -c` subprocess. Mock functions are injected **before** the call to replace system commands (`apt-get`, `yum`, `curl`, `openssl`, etc.) and internal helpers (`common_logger`, `installCommon_rollBack`, ...) so no real packages are installed or system state is modified.

### Core helper — `conftest.py`

```python
from tests.unit.conftest import run_bash_function, assert_success, assert_failure

result = run_bash_function(
    source_files=["common_functions/common.sh", "install_functions/indexer.sh"],
    func_call="indexer_install",
    mock_funcs={
        "common_logger":        "true",          # suppress log output
        "yum":                  "true",           # pretend install succeeds
        "installCommon_rollBack": "true",
    },
    env_vars={
        "sys_type":         "yum",
        "sep":              "-",
        "indexer_version":  "5.0.0",
        "indexer_revision": "1",
    },
)

assert_success(result)   # asserts returncode == 0
assert_failure(result)   # asserts returncode != 0
```

`run_bash_function` returns a `subprocess.CompletedProcess` with `.returncode`, `.stdout`, and `.stderr` for full inspection.

### Example — testing a failure path

```python
def test_fail_yum_package_error(self):
    result = self._run("yum", "-", pkg_success=False)
    assert_failure(result)
```

The `pkg_success=False` case injects `"yum": "return 1"` so the package installation fails, and the test asserts the function exits non-zero.

## Writing a new test

1. Identify the bash file and function to test (e.g. `install_functions/manager.sh` → `manager_install`).
2. Create `tests/unit/test_<module>.py`.
3. Import helpers and define source files:

```python
from tests.unit.conftest import assert_failure, assert_success, run_bash_function

MANAGER = "install_functions/manager.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, MANAGER]
IGNORE_LOGGER = {"common_logger": "true"}
```

4. Write test classes grouped by function under test:

```python
class TestManagerInstall:
    def _run(self, sys_type, sep, pkg_success=True):
        mocks = {
            **IGNORE_LOGGER,
            sys_type: "true" if pkg_success else "return 1",
            "installCommon_rollBack": "true",
        }
        return run_bash_function(
            BASE_SOURCES,
            "manager_install",
            mocks,
            {"sys_type": sys_type, "sep": sep,
             "manager_version": "5.0.0", "manager_revision": "1"},
        )

    def test_success_apt(self):
        assert_success(self._run("apt-get", "="))

    def test_fail_apt_error(self):
        assert_failure(self._run("apt-get", "=", pkg_success=False))
```

## CI integration

Tests run automatically on every PR via [`.github/workflows/check_unit_tests.yaml`](../../.github/workflows/check_unit_tests.yaml):
- Triggered on `ready_for_review` and `synchronize` events (non-draft PRs only).
- Runs `hatch run dev:test-cov` and posts a bot comment on the PR with the results and coverage table.
- Fails the workflow if any test fails.

## Legacy tests

The original Bach/Docker-based test suites are preserved in [`legacy/`](legacy/) for historical reference. They are **not executed** by the CI pipeline or by Hatch. See [`legacy/README.md`](legacy/README.md) for their original usage instructions.
