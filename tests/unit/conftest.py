"""
Shared fixtures and helpers for wazuh-installation-assistant unit tests.

Pattern: each test calls bash functions via subprocess, injecting mock
functions through bash function overriding to avoid real system calls.
"""

import shlex
import subprocess
import textwrap
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent


def run_bash_function(
    source_files: list[str],
    func_call: str,
    mock_funcs: dict[str, str] | None = None,
    env_vars: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run a bash function with optional command/function mocking.

    Args:
        source_files: List of bash files to source, relative to PROJECT_ROOT.
        func_call: The function call to execute (e.g. "checks_arch").
        mock_funcs: Dict mapping command/function names to their mock body.
            Example: {"uname": "echo x86_64", "common_logger": "true"}
        env_vars: Additional environment variables to set before the call.
            Values starting with '(' and ending with ')' are treated as bash
            arrays and set with 'declare -a' instead of 'export'.

    Returns:
        CompletedProcess with returncode, stdout, stderr.
    """
    sources = "\n".join(
        f'source "{PROJECT_ROOT / f}"' for f in source_files
    )

    mocks = ""
    if mock_funcs:
        for name, body in mock_funcs.items():
            mocks += textwrap.dedent(f"""\
                function {name} {{ {body}; }}
                export -f {name}
            """)

    env_exports = ""
    if env_vars:
        for k, v in env_vars.items():
            stripped = v.strip()
            if stripped.startswith("(") and stripped.endswith(")"):
                env_exports += f"declare -a {k}={stripped}\n"
            else:
                env_exports += f'export {k}={shlex.quote(v)}\n'

    script = f"""
set +e
{sources}
{mocks}
{env_exports}
{func_call}
"""
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )


def assert_success(result: subprocess.CompletedProcess) -> None:
    """Assert that a bash function call returned exit code 0."""
    assert result.returncode == 0, (
        f"Expected success (exit 0) but got exit {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def assert_failure(result: subprocess.CompletedProcess) -> None:
    """Assert that a bash function call returned a non-zero exit code."""
    assert result.returncode != 0, (
        f"Expected failure (exit != 0) but got exit {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


@pytest.fixture
def bash_runner():
    """Fixture that returns the run_bash_function helper."""
    return run_bash_function
