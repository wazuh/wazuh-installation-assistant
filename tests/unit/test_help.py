"""
Exit codes of getHelp in the installation assistant, the certs tool and the
passwords tool: 0 when the help is asked for, 1 when it is shown after an error.
"""

import pytest

from tests.unit.conftest import assert_success, run_bash_function

COMMON_VARS = "common_functions/commonVariables.sh"
COMMON = "common_functions/common.sh"
MAINS = [
    "install_functions/installMain.sh",
    "cert_tool/certMain.sh",
    "passwords_tool/passwordsMain.sh",
]


@pytest.mark.parametrize("main_file", MAINS)
def test_help_asked_exits_0(main_file):
    assert_success(run_bash_function([COMMON_VARS, COMMON, main_file], "getHelp 0"))


@pytest.mark.parametrize("main_file", MAINS)
def test_help_after_error_exits_1(main_file):
    result = run_bash_function([COMMON_VARS, COMMON, main_file], "getHelp")
    assert result.returncode == 1


@pytest.mark.parametrize("args", ["-h", "--help"])
def test_install_main_help_exits_0(args):
    result = run_bash_function(
        [COMMON_VARS, COMMON, "install_functions/installMain.sh"],
        f"main {args}",
        {"installCommon_logRunHeader": "true"},
    )
    assert_success(result)
    assert "--development" in result.stdout


@pytest.mark.parametrize("args", ["", "--no-such-option"])
def test_install_main_no_args_or_unknown_option_exits_1(args):
    result = run_bash_function(
        [COMMON_VARS, COMMON, "install_functions/installMain.sh"],
        f"main {args}",
        {"installCommon_logRunHeader": "true"},
    )
    assert result.returncode == 1
