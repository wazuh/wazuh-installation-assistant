# Unit Tests — Wazuh Installation Assistant

Unit tests for the bash scripts in this repository. Tests are written in **Python pytest** and run bash functions directly via `subprocess`, with mock injection to avoid real system calls. No Docker required.

## Structure

```
tests/unit/
├── conftest.py                  # Shared helpers: run_bash_function, assert_success, assert_failure
├── test_checks.py               # checks.sh — argument validation, arch, health, cert checks
├── test_common.py               # common.sh — system detection, package manager checks
├── test_cert_functions.py       # certFunctions.sh — cert generation, OpenSSL checks, config parsing
├── test_passwords_functions.py  # passwordsFunctions.sh — password validation, generation, API token
├── test_install_common.py       # installCommon.sh — config retrieval, prerequisites, service start
├── test_manager.py              # manager.sh — install (apt/yum), cluster start
├── test_indexer.py              # indexer.sh — install (apt/yum), configure
├── test_dashboard.py            # dashboard.sh — install (apt/yum), configure
└── legacy/                      # Preserved Bach/Docker tests (not executed, kept as reference)
```

## Requirements

- Python >= 3.11
- [Hatch](https://hatch.pypa.io/) (`pip install hatch`)
- `bash` available on the host (standard on Linux/macOS)

## Running the tests

### With Hatch (recommended — mirrors CI)

```bash
# Run all unit tests
hatch run dev:test

# Run with coverage report
hatch run dev:test-cov
```

### With pytest directly

```bash
# From the repository root
pip install pytest pytest-xdist pytest-cov
pytest tests/unit/ -v

# Run a single test file
pytest tests/unit/test_passwords_functions.py -v

# Run a single test class or method
pytest tests/unit/test_passwords_functions.py::TestPasswordsCheckPassword -v
pytest tests/unit/test_passwords_functions.py::TestPasswordsCheckPassword::test_fail_no_uppercase -v

# Filter by keyword
pytest tests/unit/ -k "fail"
pytest tests/unit/ -k "apt"
```

---

## How tests work

The source code of this project is entirely **bash scripts**. There is no Python application to test. Instead, each test:

1. Builds a bash script dynamically (source files + mock functions + env vars + function call).
2. Runs it in a `bash -c` subprocess.
3. Asserts the exit code (and optionally the output).

### The full flow — step by step

Take this test as an example:

```python
def test_fail_no_uppercase(self):
    result = self._run("invalidpass1.")
    assert_failure(result)
```

**Step 1** — `_run` calls `run_bash_function` (defined in `conftest.py`):

```python
def _run(self, password):
    return run_bash_function(
        source_files=["common_functions/commonVariables.sh",
                       "common_functions/common.sh",
                       "passwords_tool/passwordsFunctions.sh"],
        func_call=f'passwords_checkPassword "{password}"',
        mock_funcs={
            "common_logger":          "true",
            "installCommon_rollBack": "true",
        },
    )
```

**Step 2** — `run_bash_function` assembles a bash script string:

```bash
set +e

source "/repo/common_functions/commonVariables.sh"
source "/repo/common_functions/common.sh"
source "/repo/passwords_tool/passwordsFunctions.sh"

function common_logger { true; }
export -f common_logger

function installCommon_rollBack { true; }
export -f installCommon_rollBack

passwords_checkPassword "invalidpass1."
```

**Step 3** — Python runs the script in a subprocess:

```python
subprocess.run(["bash", "-c", script], capture_output=True, text=True)
```

**Step 4** — The real bash function runs with the mocked commands injected. In `passwordsFunctions.sh`:

```bash
function passwords_checkPassword() {
    if ! echo "$1" | grep -q "[A-Z]" || \
       ! echo "$1" | grep -q "[a-z]" || \
       ! echo "$1" | grep -q "[0-9]" || \
       ! echo "$1" | grep -q "[.*+?-]" || \
       [ "${#1}" -lt 8 ] || [ "${#1}" -gt 64 ]; then
        common_logger -e "The password must have ..."
        installCommon_rollBack
        exit 1
    fi
}
```

With `"invalidpass1."`:
- No uppercase → condition is true → enters the `if` block → calls `common_logger` (mock, does nothing) → calls `installCommon_rollBack` (mock, does nothing) → `exit 1`.

**Step 5** — Python receives `returncode=1`. `assert_failure` passes.

---

## Mocking

Mocking means **replacing a real command or function with a fake one** that returns a controlled output or exit code, so the test does not depend on external systems (network, disk, installed packages).

In bash, any function or command can be overridden by defining a new function with the same name:

```bash
function curl { echo 'fake response'; }
export -f curl
```

After this line, any call to `curl` in the script — including inside sourced files — runs your fake version instead.

`run_bash_function` injects mocks by generating these function definitions and placing them **after** the `source` calls (so the sources load first) but **before** the function call under test.

### The three types of mock

#### 1. Silencer — suppress a call entirely

```python
{"common_logger": "true"}
```

```bash
function common_logger { true; }
```

`true` is a bash built-in that does nothing and exits 0. Use this for logger calls, rollback hooks, or any function you want to completely ignore.

---

#### 2. Output mock — return a controlled response

```python
{"curl": "echo 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.valid'"}
```

```bash
function curl { echo 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.valid'; }
```

The real `curl` would make an HTTP request to the Wazuh API. The mock echoes a fake JWT token directly. This lets you test that the code handles a valid token correctly — without a running API server.

You can also simulate failure by returning a non-zero exit code:

```python
{"openssl": "return 1"}
```

```bash
function openssl { return 1; }
```

---

#### 3. Conditional mock — respond differently based on arguments

```python
{
    "command": (
        'case "$2" in '
        'yum) echo /usr/bin/yum ;; '
        'apt-get) return 1 ;; '
        '*) return 1 ;; esac'
    )
}
```

```bash
function command {
    case "$2" in
        yum)     echo /usr/bin/yum ;;
        apt-get) return 1 ;;
        *)       return 1 ;;
    esac
}
```

This simulates a system where `yum` is installed but `apt-get` is not. The test for `common_checkSystem` calls `command -v yum` and `command -v apt-get` internally — the mock handles both.

---

### Real example: testing the API token function

```python
class TestPasswordsGetApiToken:

    def test_success_valid_token(self):
        mocks = {
            "common_logger": "true",
            "curl": "echo 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.valid'",
            "sleep": "true",   # avoid real delays between retries
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"adminUser": "admin", "adminPassword": "pass"},
        )
        assert_success(result)

    def test_fail_invalid_credentials(self):
        mocks = {
            "common_logger": "true",
            "curl": "echo 'Invalid credentials'",
            "sleep": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"adminUser": "admin", "adminPassword": "wrongpass"},
        )
        assert_failure(result)
```

In `test_success_valid_token`, the mock `curl` returns a string that starts with `eyJ` (a JWT token). The function detects it as a valid token and exits 0.

In `test_fail_invalid_credentials`, the mock `curl` returns `"Invalid credentials"`. The function detects that string and exits 1.

The Wazuh API server is never contacted. The test runs in milliseconds.

---

## Test isolation — one condition per test

Each test should change **exactly one thing** from the valid/happy-path baseline. If a test input violates two rules at once, you cannot know which rule the code is actually checking.

### Wrong — two conditions failing at once

```python
def test_fail_no_uppercase(self):
    result = self._run("invalidpass1!")
    assert_failure(result)
```

This passes, but not necessarily because of the missing uppercase. `!` is also not in the valid symbol set `[.*+?-]`, so the function could be exiting for either reason. If someone later adds `!` to the valid symbols, the test still passes — but for the wrong reason.

### Correct — only one condition fails

```python
def test_fail_no_uppercase(self):
    result = self._run("invalidpass1.")
    assert_failure(result)
```

Now every other requirement is satisfied. If the test fails (i.e., the function exits 0), it can only be because the uppercase check is broken.

### Baseline for `passwords_checkPassword`

The valid symbol set accepted by bash is exactly: `. * + ? -`

| Test | Input | Only condition violated |
|---|---|---|
| `test_success_valid_password` | `"ValidPass1."` | none — all valid |
| `test_fail_no_uppercase` | `"invalidpass1."` | no uppercase |
| `test_fail_no_lowercase` | `"INVALIDPASS1."` | no lowercase |
| `test_fail_no_digit` | `"InvalidPass."` | no digit |
| `test_fail_no_symbol` | `"InvalidPass1"` | no symbol |
| `test_fail_too_short` | `"V1.a"` | length < 8 |
| `test_fail_too_long` | `"A"*61 + "1.aB"` | length > 64 |

---

## Environment variables and bash arrays

Some bash functions read global variables. Pass them via `env_vars`:

```python
result = run_bash_function(
    BASE_SOURCES,
    "passwords_checkUser",
    mock_funcs={"common_logger": "true"},
    env_vars={
        "users": "(wazuh admin kibanaserver)",
        "nuser": "admin",
    },
)
```

**Important:** values that look like `(item1 item2)` are automatically declared as bash arrays using `declare -a`, not `export`. This is necessary because bash arrays cannot be exported as environment variables — they must be declared in the same shell session.

Internally, `conftest.py` generates:

```bash
declare -a users=(wazuh admin kibanaserver)
export nuser="admin"
```

---

## Writing a new test

1. Identify the bash file and function to test, e.g. `install_functions/manager.sh` → `manager_install`.
2. Create `tests/unit/test_<module>.py`.
3. Import helpers and declare source file paths:

```python
from tests.unit.conftest import assert_failure, assert_success, run_bash_function

MANAGER      = "install_functions/manager.sh"
COMMON       = "common_functions/common.sh"
COMMON_VARS  = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, MANAGER]
IGNORE_LOGGER = {"common_logger": "true"}
```

4. Group tests in classes by function under test. Use a `_run` helper to avoid repeating boilerplate:

```python
class TestManagerInstall:
    def _run(self, sys_type, sep, tmp_path, pkg_install_success=True):
        ext = "rpm" if sys_type == "yum" else "deb"
        pkg_dir = tmp_path / "packages"
        pkg_dir.mkdir()
        (pkg_dir / f"wazuh-manager-1.2.3.x86_64.{ext}").touch()

        install_result  = "0" if pkg_install_success else "1"
        wazuh_installed = "1" if pkg_install_success else ""

        mocks = {
            **IGNORE_LOGGER,
            "installCommon_yumInstall": f"install_result={install_result}",
            "installCommon_aptInstall": f"install_result={install_result}",
            "common_checkInstalled":   f"wazuh_installed={wazuh_installed}; install_result={install_result}",
            "installCommon_rollBack":  "true",
        }
        return run_bash_function(
            BASE_SOURCES,
            "manager_install",
            mocks,
            {
                "sys_type":                    sys_type,
                "sep":                         sep,
                "wazuh_version":               "1.2.3",
                "wazuh_revision":              "1",
                "base_path":                   str(tmp_path),
                "download_packages_directory": "packages",
            },
        )

    def test_success_yum_install(self, tmp_path):
        assert_success(self._run("yum", "-", tmp_path))

    def test_success_apt_install(self, tmp_path):
        assert_success(self._run("apt-get", "=", tmp_path))

    def test_fail_yum_install_error(self, tmp_path):
        assert_failure(self._run("yum", "-", tmp_path, pkg_install_success=False))
```

5. Verify isolation: each `test_fail_*` should have only **one** condition that differs from the valid baseline.

---

## CI integration

Tests run automatically on every PR via [`.github/workflows/check_unit_tests.yaml`](../../.github/workflows/check_unit_tests.yaml):

- Triggered on `ready_for_review` and `synchronize` events (non-draft PRs only).
- Runs `hatch run dev:test-cov` and posts a bot comment with results and coverage.
- Fails the workflow if any test fails.

---

## About coverage

The coverage report measures **Python code** (the test files and `conftest.py`), not the bash scripts. Since the source code is bash, Python coverage cannot track which lines of the bash functions were exercised.

The coverage numbers reflect how much of the test infrastructure itself runs — `conftest.py` at 96% means one helper function (`bash_runner` fixture) is defined but not used by any test. This is expected and not a problem.

To check which bash code paths are exercised, review the test cases manually and ensure both the success and failure branches of each bash function are covered by at least one test.

---

## Legacy tests

The original Bach/Docker-based test suites are preserved in [`legacy/`](legacy/) for historical reference. They are **not executed** by the CI pipeline or by Hatch. See [`legacy/README.md`](legacy/README.md) for their original usage instructions.
