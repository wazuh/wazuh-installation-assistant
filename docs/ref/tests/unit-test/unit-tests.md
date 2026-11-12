# Unit tests

Unit tests for the Wazuh Installation Assistant scripts. Tests are written in **Python pytest** and run bash functions directly via `subprocess`, with mock injection to avoid real system calls. On Linux, no Docker is required.

## Requirements

- Python >= 3.11
- [Hatch](https://hatch.pypa.io/) — recommended (`pip install hatch`)
- A Linux host with `bash`, `ps` and `pkill` (`procps`), as on the CI runners. The tests create `/run/systemd/system` when it is missing, so run them as root or with that directory already in place. They do not run on macOS, where that directory cannot be created: use a Linux container instead, for example `docker run --rm -it -v "$PWD":/repo -w /repo python:3.12 bash`, and install `procps` in it.

## Test structure

Tests live in `tests/unit/` alongside their configuration.

```
tests/unit/
├── README.md
├── conftest.py                  # Shared helpers: run_bash_function, assert_success, assert_failure
├── fixtures/
├── test_checks.py               # checks.sh — argument validation, arch, health, cert checks
├── test_common.py               # common.sh — system detection, package manager checks
├── test_cert_functions.py       # certFunctions.sh — cert generation, OpenSSL checks, config parsing
├── test_passwords_functions.py  # passwordsFunctions.sh — password validation, generation, API token
├── test_passwords_main.py       # passwordsMain.sh — argument parsing, change-all and single-user flows
├── test_help.py                 # getHelp exit codes of the three tools
├── test_offline.py              # wazuh-offline-installation.sh — offline_extractFiles
├── test_credentials.py          # credentials.sh — env files, password rules and generation, root CA
├── test_install_common.py       # installCommon.sh — config retrieval, prerequisites, service start
├── test_manager.py              # manager.sh — install (apt/yum), cluster start
├── test_indexer.py              # indexer.sh — install (apt/yum), configure
└── test_dashboard.py            # dashboard.sh — install (apt/yum), configure
```

### Bash modules covered

| Test file | Bash module |
| --------- | ----------- |
| `test_checks.py` | `install_functions/checks.sh` |
| `test_common.py` | `common_functions/common.sh` |
| `test_cert_functions.py` | `cert_tool/certFunctions.sh` |
| `test_passwords_functions.py` | `passwords_tool/passwordsFunctions.sh` |
| `test_passwords_main.py` | `passwords_tool/passwordsMain.sh` |
| `test_help.py` | `install_functions/installMain.sh`, `cert_tool/certMain.sh`, `passwords_tool/passwordsMain.sh` (`getHelp`) |
| `test_offline.py` | `install_functions/wazuh-offline-installation.sh` |
| `test_credentials.py` | `common_functions/credentials.sh` |
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
pytest tests/unit/test_passwords_functions.py::TestPasswordsCheckPassword::test_error_names_the_missing_class -v

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

The following example tests that `passwords_checkPassword` rejects a password without a symbol and names the missing class:

```python
def test_error_names_the_missing_class(self):
    result = self._run("Abcdefghij12")
    assert "password must contain at least one symbol" in result.stdout
```

**Step 1** — `_run` calls `run_bash_function` (defined in `conftest.py`):

```python
def _run(self, password):
    return run_bash_function(
        BASE_SOURCES,
        'passwords_checkPassword "${CHECKED}"',
        {"common_logger": 'echo "LOG:$*"'},
        {"CHECKED": password},
    )
```

`BASE_SOURCES` lists `common_functions/commonVariables.sh`, `common_functions/common.sh`, `common_functions/credentials.sh`, `passwords_tool/passwordsVariables.sh` and `passwords_tool/passwordsFunctions.sh`.

**Step 2** — `run_bash_function` assembles a bash script string:

```bash
set +e

source "/repo/common_functions/commonVariables.sh"
source "/repo/common_functions/common.sh"
source "/repo/common_functions/credentials.sh"
source "/repo/passwords_tool/passwordsVariables.sh"
source "/repo/passwords_tool/passwordsFunctions.sh"

function common_logger { echo "LOG:$*"; }
export -f common_logger

export CHECKED=Abcdefghij12

passwords_checkPassword "${CHECKED}"
```

**Step 3** — Python runs the script in a subprocess:

```python
subprocess.run(["bash", "-c", script], capture_output=True, text=True)
```

**Step 4** — The real bash function runs with the mocked commands injected. `passwords_checkPassword` calls `common_passwordValidate`, which checks the character set, the length, and the lowercase, uppercase, digit, and symbol requirements. With `"Abcdefghij12"` (no symbol), it returns 1 with the reason. `passwords_checkPassword` passes the reason to `common_logger` (mock — prints `LOG:-e Invalid password: password must contain at least one symbol from . , _ + : @ % ^ = ~ -.`), then exits 1.

**Step 5** — Python receives `returncode=1` and the mock output in `stdout`. The assertion on the message passes.

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
REJECTED = [
    "abcdefghij1!",   # no uppercase letter, but ! is also not a valid symbol
]
```

This passes, but not because of the missing uppercase: `common_passwordValidate` checks the character set first and rejects the `!` before it reaches the uppercase check. If the uppercase check breaks, the test still passes — for the wrong reason.

### Correct — only one condition fails

```python
REJECTED = [
    "abcdefghij1.",   # . is valid; only uppercase is missing
]
```

Now every other requirement is satisfied. If the test fails (function exits 0), it can only be because the uppercase check is broken.

### Baseline for `passwords_checkPassword`

The rule is the one of `common_passwordValidate` in `common_functions/credentials.sh`: 12 to 64 characters, with at least one lowercase letter, one uppercase letter, one digit, and one symbol. The valid symbol set accepted by the bash function is exactly: `. , _ + : @ % ^ = ~ -`. Any other character, such as `*`, `?` or `!`, is rejected.

The inputs live in the `ACCEPTED` and `REJECTED` lists of `tests/unit/test_passwords_functions.py`. Some of them:

| Test | Input | Only condition violated |
| ---- | ----- | ----------------------- |
| `test_success` | `"Abcdefghij1."` | none — all conditions satisfied |
| `test_fail` | `"abcdefghij1."` | no uppercase letter |
| `test_fail` | `"ABCDEFGHIJ1."` | no lowercase letter |
| `test_fail` | `"Abcdefghijk."` | no digit |
| `test_fail` | `"Abcdefghij12"` | no valid symbol |
| `test_fail` | `"Abcdefghi1."` | length < 12 |
| `test_fail` | `"Aa1." + "b" * 61` | length > 64 |
| `test_fail` | `"Abcdefghij1." + character` | character outside the set (for example `*` or `?`) |

`test_same_answer_as_the_helper` runs every input of both lists through `passwords_checkPassword` and `common_passwordValidate` and checks that they give the same answer.

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

Unit tests run automatically on every pull request via [`.github/workflows/5_check_unit_tests.yaml`](../../../../.github/workflows/5_check_unit_tests.yaml):

- Triggered on `ready_for_review` and `synchronize` events (non-draft PRs only).
- Runs `hatch run dev:test-cov` using Python 3.12.
- Parses the output to extract the test summary and coverage table.
- Posts a bot comment on the PR with pass/fail status, a coverage details block, and a list of failed tests (if any).
- Uploads `test_output.txt` and `failed_tests.txt` as artifacts with a 7-day retention period.
- Fails the workflow if any test fails, blocking the PR.

## About coverage

The coverage report measures **Python code** (the test files and `conftest.py`), not the bash scripts. Since the source code is bash, Python coverage cannot track which lines of the bash functions were exercised.

The coverage numbers reflect how much of the test infrastructure itself runs. `conftest.py` is not fully covered: the `bash_runner` fixture is defined but not used by any test, and the branch that creates `/run/systemd/system` only runs where that directory is missing. This is expected and not a problem.

To check which bash code paths are exercised, review the test cases manually and ensure both the success and failure branches of each bash function are covered by at least one test.
