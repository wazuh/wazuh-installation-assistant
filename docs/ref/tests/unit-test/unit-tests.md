# Unit tests

Unit tests for the Wazuh Installation Assistant scripts. Tests are written in **Python pytest** and run bash functions directly via `subprocess`, with mock injection to avoid real system calls. No Docker required.

## Requirements

- Python >= 3.11
- [Hatch](https://hatch.pypa.io/) — recommended (`pip install hatch`)
- `bash` available on the host (standard on Linux/macOS)

## Test structure

Tests live in `tests/unit/` alongside their configuration. Legacy Bach/Docker-based tests are preserved in `tests/unit/legacy/` for historical reference but are not executed by the CI pipeline.

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

### Bash modules covered

| Test file | Bash module |
| --------- | ----------- |
| `test_checks.py` | `install_functions/checks.sh` |
| `test_common.py` | `common_functions/common.sh` |
| `test_cert_functions.py` | `install_functions/certFunctions.sh` |
| `test_passwords_functions.py` | `passwords_tool/passwordsFunctions.sh` |
| `test_install_common.py` | `install_functions/installCommon.sh` |
| `test_manager.py` | `install_functions/manager.sh` |
| `test_indexer.py` | `install_functions/indexer.sh` |
| `test_dashboard.py` | `install_functions/dashboard.sh` |

## Running the tests

### With Hatch (recommended — mirrors CI)

```bash
# Run all unit tests
hatch run dev:test

# Run with coverage report
hatch run dev:test-cov
```

Hatch creates an isolated Python 3.11 virtual environment with the correct dependency versions automatically. The `dev:test-cov` command is the same one used by the CI pipeline.

### With pytest directly

```bash
# Install dependencies
pip install pytest pytest-cov pytest-xdist

# Run all tests with verbose output (from repository root)
pytest tests/unit/ -v

# Run a single test file
pytest tests/unit/test_passwords_functions.py -v

# Run a single test class
pytest tests/unit/test_passwords_functions.py::TestPasswordsCheckPassword -v

# Run a single test method
pytest tests/unit/test_passwords_functions.py::TestPasswordsCheckPassword::test_fail_no_uppercase -v

# Filter by keyword across all files
pytest tests/unit/ -k "fail"
pytest tests/unit/ -k "apt"
pytest tests/unit/ -k "aio"
```

## How the tests work

The source code of this project is entirely bash scripts. There is no Python application to test. Instead, each test:

1. Builds a bash script dynamically (source files + mock functions + env vars + function call).
2. Runs it in a `bash -c` subprocess.
3. Asserts the exit code (and optionally the output).

### Step-by-step flow

The following example tests that `passwords_checkPassword` rejects a password without an uppercase letter:

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

**Step 4** — The real bash function runs with the mocked commands injected. The function checks for uppercase, lowercase, digit, and symbol requirements. With `"invalidpass1."` (no uppercase), it calls `common_logger` (mock — does nothing), calls `installCommon_rollBack` (mock — does nothing), then exits 1.

**Step 5** — Python receives `returncode=1`. `assert_failure(result)` passes.

## Mocking

Mocking means **replacing a real command or function with a fake one** that returns a controlled output or exit code, so the test does not depend on external systems (network, disk, installed packages).

In bash, any function or command can be overridden by defining a new function with the same name. `run_bash_function` injects mocks by generating these definitions and placing them **after** the `source` calls (so the sources load first) but **before** the function call under test.

### Type 1 — Silencer

Suppress a call entirely, always succeeds:

```python
{"common_logger": "true"}
```

Generates:

```bash
function common_logger { true; }
export -f common_logger
```

Use this for logger calls, rollback hooks, or any function you want to completely ignore.

### Type 2 — Output mock

Return a controlled response:

```python
{"curl": "echo 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.valid'"}
```

Generates:

```bash
function curl { echo 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.valid'; }
export -f curl
```

The real `curl` would make an HTTP request to the Wazuh API. The mock echoes a fake JWT token directly. You can also simulate failure:

```python
{"openssl": "return 1"}
```

### Type 3 — Conditional mock

Respond differently based on arguments:

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

Generates:

```bash
function command {
    case "$2" in
        yum)     echo /usr/bin/yum ;;
        apt-get) return 1 ;;
        *)       return 1 ;;
    esac
}
export -f command
```

This simulates a system where `yum` is installed but `apt-get` is not. The `common_checkSystem` function calls `command -v yum` and `command -v apt-get` internally — the mock handles both with a single function.

## Test isolation

Each test should change **exactly one thing** from the valid/happy-path baseline. If a test input violates two rules at once, you cannot know which rule the code is actually checking.

### Wrong — two conditions failing at once

```python
def test_fail_no_uppercase(self):
    result = self._run("invalidpass1!")   # ! is also not a valid symbol
    assert_failure(result)
```

This passes, but not necessarily because of the missing uppercase. If someone later adds '!' to the valid symbol set, the test still passes — but for the wrong reason.

### Correct — only one condition fails

```python
def test_fail_no_uppercase(self):
    result = self._run("invalidpass1.")   # . is valid; only uppercase is missing
    assert_failure(result)
```

Now every other requirement is satisfied. If the test fails (function exits 0), it can only be because the uppercase check is broken.

### Baseline for `passwords_checkPassword`

The valid symbol set accepted by the bash function is exactly: `. * + ? -`

| Test | Input | Only condition violated |
| ---- | ----- | ----------------------- |
| `test_success_valid_password` | `"ValidPass1."` | none — all conditions satisfied |
| `test_fail_no_uppercase` | `"invalidpass1."` | no uppercase letter |
| `test_fail_no_lowercase` | `"INVALIDPASS1."` | no lowercase letter |
| `test_fail_no_digit` | `"InvalidPass."` | no digit |
| `test_fail_no_symbol` | `"InvalidPass1"` | no valid symbol |
| `test_fail_too_short` | `"V1.a"` | length < 8 |
| `test_fail_too_long` | `"A" * 61 + "1.aB"` | length > 64 |

## Environment variables and bash arrays

Some bash functions read global variables. Pass them via the `env_vars` argument:

```python
result = run_bash_function(
    source_files=BASE_SOURCES,
    func_call="passwords_checkUser",
    mock_funcs={"common_logger": "true"},
    env_vars={
        "users": "(wazuh admin kibanaserver)",
        "nuser": "admin",
    },
)
```

> **note**: Values that look like `(item1 item2)` are automatically declared as bash arrays using `declare -a`, not `export`. This is necessary because bash arrays cannot be exported as environment variables — they must be declared in the same shell session.

Internally, `conftest.py` generates:

```bash
declare -a users=(wazuh admin kibanaserver)
export nuser="admin"
```

## CI integration

Unit tests run automatically on every pull request via [`.github/workflows/check_unit_tests.yaml`](../../../.github/workflows/check_unit_tests.yaml):

- Triggered on `ready_for_review` and `synchronize` events (non-draft PRs only).
- Runs `hatch run dev:test-cov` using Python 3.12.
- Parses the output to extract the test summary and coverage table.
- Posts a bot comment on the PR with pass/fail status, a coverage details block, and a list of failed tests (if any).
- Uploads `test_output.txt` and `failed_tests.txt` as artifacts with a 7-day retention period.
- Fails the workflow if any test fails, blocking the PR.

## About coverage

The coverage report measures **Python code** (the test files and `conftest.py`), not the bash scripts. Since the source code is bash, Python coverage cannot track which lines of the bash functions were exercised.

The coverage numbers reflect how much of the test infrastructure itself runs. A `conftest.py` coverage of 96% means one helper (the `bash_runner` fixture) is defined but not used by any test. This is expected and not a problem.

To check which bash code paths are exercised, review the test cases manually and ensure both the success and failure branches of each bash function are covered by at least one test.
