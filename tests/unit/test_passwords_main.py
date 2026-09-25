"""
Unit tests for passwords_tool/passwordsMain.sh

Covers: argument parsing and validation, and the two top-level flows driven
by `main`:
- the -a|--change-all batch flow (indexer only, manager only, and both)
- the single-user (-u|--user) flow, with a password read from the standard
  input (-p|--password) or generated.

`common_checkRoot`, `common_checkSystem` and `common_checkInstalled` are
mocked so tests never depend on the real host (root permissions, package
manager, installed Wazuh components). The `passwords_*` functions that
would otherwise touch the real filesystem, systemd, the credentials file or
the Wazuh components are mocked to print a marker on stdout, so each test
can assert exactly which code path `main` took without executing any real
system operation.
"""

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

COMMON_VARS = "common_functions/commonVariables.sh"
COMMON = "common_functions/common.sh"
CREDENTIALS = "credentials_lib/wazuh-credentials.sh"
PASSWORDS_VARS = "passwords_tool/passwordsVariables.sh"
PASSWORDS_FUNCTIONS = "passwords_tool/passwordsFunctions.sh"
PASSWORDS_MAIN = "passwords_tool/passwordsMain.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, CREDENTIALS, PASSWORDS_VARS, PASSWORDS_FUNCTIONS, PASSWORDS_MAIN]

# Base mock set: silences/short-circuits everything main() can call so a
# test only has to override what it cares about (system checks + the
# installed-component flags). Every passwords_* mock announces itself on
# stdout so tests can assert exactly which functions ran.
BASE_MOCKS = {
    "common_checkRoot": "true",
    "common_checkSystem": "true",
    "passwords_checkCredentialsFile": 'echo "CHECKCREDENTIALSFILE_CALLED"',
    "passwords_readUsers": 'echo "READUSERS_CALLED"; users=(admin kibanaserver wazuh-manager)',
    "passwords_checkUser": 'echo "CHECKUSER_CALLED"',
    "passwords_readPassword": 'echo "READPASSWORD_CALLED"; password="ValidPass1234"',
    "passwords_generatePassword": 'echo "GENERATEPASSWORD_CALLED"; password="AutoGenPass1234"',
    "passwords_generatePasswords": 'echo "GENERATEPASSWORDS_CALLED"',
    "passwords_checkPassword": 'echo "CHECKPASSWORD_CALLED:$*"',
    "passwords_getNetworkHost": 'echo "GETNETWORKHOST_CALLED"',
    "passwords_generateHash": 'echo "GENERATEHASH_CALLED"',
    "passwords_changePassword": 'echo "CHANGEPASSWORD_CALLED"',
    "passwords_runSecurityAdmin": 'echo "RUNSECURITYADMIN_CALLED"',
    "passwords_saveIndexerCredentials": 'echo "SAVEINDEXERCREDENTIALS_CALLED"',
    "passwords_isServiceActive": 'echo "ISSERVICEACTIVE_CALLED:$*"; return 0',
    "passwords_changePasswordApi": 'echo "CHANGEPASSWORDAPI_CALLED:${api_users[*]}"',
    "passwords_restartService": 'echo "RESTARTSERVICE_CALLED:$1"',
}


def _run(args, extra_mocks=None, checkinstalled="true"):
    mocks = {
        **BASE_MOCKS,
        "common_checkInstalled": checkinstalled,
        **(extra_mocks or {}),
    }
    return run_bash_function(BASE_SOURCES, f"main {args}", mocks)


class TestPasswordsMainArguments:
    """Argument validation.

    Each case changes exactly one condition away from a valid baseline
    ("-a", "-u admin" or "-u admin -p"), so a passing test can only be
    explained by the specific validation under test.
    """

    def test_fail_no_user_and_no_changeall(self):
        result = _run("-v")
        assert_failure(result)

    def test_fail_changeall_with_user(self):
        result = _run("-a -u admin")
        assert_failure(result)

    def test_fail_changeall_with_password(self):
        result = _run("-a -p")
        assert_failure(result)

    def test_fail_password_without_user(self):
        result = _run("-p", checkinstalled="indexer_installed=1")
        assert_failure(result)
        assert "READPASSWORD_CALLED" not in result.stdout

    def test_fail_password_on_the_command_line(self):
        """-p takes no value: a password on the command line is visible in ps,
        so the value left behind is an unknown option and the tool refuses it."""
        result = _run("-u admin -p ValidPass1234", checkinstalled="indexer_installed=1")
        assert_failure(result)
        assert "CHANGEPASSWORD_CALLED" not in result.stdout

    def test_fail_removed_api_admin_options(self):
        """-au/-ap are gone: rbac_control needs no Wazuh API admin credentials."""
        result = _run("-a -au wazuh -ap AdminPass1234", checkinstalled="wazuh_installed=1")
        assert_failure(result)
        assert "CHANGEPASSWORDAPI_CALLED" not in result.stdout

    def test_fail_removed_api_flag(self):
        """-A is gone: the Wazuh API users are known by name."""
        result = _run("-A -u wazuh", checkinstalled="wazuh_installed=1")
        assert_failure(result)

    def test_success_single_user_baseline_still_works(self):
        result = _run("-u admin -p", checkinstalled="indexer_installed=1")
        assert_success(result)


class TestPasswordsMainCredentialsFileCheck:
    """A broken credentials file is reported before anything is changed."""

    def test_checked_before_any_change(self):
        result = _run("-a", checkinstalled="indexer_installed=1")
        assert_success(result)
        assert result.stdout.index("CHECKCREDENTIALSFILE_CALLED") < result.stdout.index("READUSERS_CALLED")

    def test_a_failed_check_stops_the_run(self):
        result = _run(
            "-a",
            extra_mocks={"passwords_checkCredentialsFile": 'echo "CHECKCREDENTIALSFILE_CALLED"; exit 1'},
            checkinstalled="indexer_installed=1",
        )
        assert_failure(result)
        assert "CHANGEPASSWORD_CALLED" not in result.stdout


class TestPasswordsMainChangeAllIndexerOnly:
    """-a|--change-all on a host with only the Wazuh indexer."""

    def _run_indexer(self):
        return _run("-a", checkinstalled="indexer_installed=1")

    def test_success_exit_code(self):
        assert_success(self._run_indexer())

    def test_takes_indexer_batch_path(self):
        result = self._run_indexer()
        for marker in ("READUSERS_CALLED", "GENERATEPASSWORDS_CALLED", "GETNETWORKHOST_CALLED",
                       "GENERATEHASH_CALLED", "CHANGEPASSWORD_CALLED", "RUNSECURITYADMIN_CALLED",
                       "SAVEINDEXERCREDENTIALS_CALLED"):
            assert marker in result.stdout

    def test_does_not_take_api_path(self):
        result = self._run_indexer()
        assert "CHANGEPASSWORDAPI_CALLED" not in result.stdout


class TestPasswordsMainChangeAllManagerOnly:
    """-a|--change-all on a host with only the Wazuh manager: the Wazuh API
    users are changed without any admin credentials."""

    def _run_manager(self):
        return _run("-a", checkinstalled="wazuh_installed=1")

    def test_success_exit_code(self):
        assert_success(self._run_manager())

    def test_takes_api_path_for_both_api_users(self):
        result = self._run_manager()
        assert "CHANGEPASSWORDAPI_CALLED:wazuh wazuh-wui" in result.stdout

    def test_does_not_take_indexer_path(self):
        result = self._run_manager()
        assert "READUSERS_CALLED" not in result.stdout
        assert "RUNSECURITYADMIN_CALLED" not in result.stdout


class TestPasswordsMainChangeAllEverything:
    """-a|--change-all on an all-in-one host: both paths run."""

    def _run_all(self):
        return _run(
            "-a",
            extra_mocks={
                "passwords_changePassword": 'echo "CHANGEPASSWORD_CALLED"; restart_manager=1; restart_dashboard=1',
            },
            checkinstalled="indexer_installed=1; wazuh_installed=1; dashboard_installed=1",
        )

    def test_success_exit_code(self):
        assert_success(self._run_all())

    def test_takes_both_paths(self):
        result = self._run_all()
        assert "RUNSECURITYADMIN_CALLED" in result.stdout
        assert "CHANGEPASSWORDAPI_CALLED:wazuh wazuh-wui" in result.stdout

    def test_restarts_run_after_security_admin(self):
        """The services must not be restarted until the new passwords have
        been applied on the Wazuh indexer."""
        result = self._run_all()
        security_admin = result.stdout.index("RUNSECURITYADMIN_CALLED")
        assert result.stdout.index("RESTARTSERVICE_CALLED:wazuh-manager") > security_admin
        assert result.stdout.index("RESTARTSERVICE_CALLED:wazuh-dashboard") > security_admin

    def test_fail_when_nothing_is_installed(self):
        result = _run("-a")
        assert_failure(result)
        assert "GENERATEPASSWORDS_CALLED" not in result.stdout


class TestPasswordsMainApiAbortStillRestarts:
    """Giving up on the Wazuh API step must not swallow the restarts that
    the Wazuh indexer side already earned."""

    def _run_api_fails(self):
        return _run(
            "-a",
            extra_mocks={
                "passwords_changePassword":
                    'echo "CHANGEPASSWORD_CALLED"; restart_dashboard=1; dashboard_keystore_updated=1',
                "passwords_changePasswordApi": 'echo "CHANGEPASSWORDAPI_CALLED"; return 1',
            },
            checkinstalled="indexer_installed=1; wazuh_installed=1; dashboard_installed=1",
        )

    def test_exits_with_an_error(self):
        assert self._run_api_fails().returncode == 1

    def test_the_dashboard_is_still_restarted(self):
        result = self._run_api_fails()
        assert "RESTARTSERVICE_CALLED:wazuh-dashboard" in result.stdout
        assert result.stdout.index("RESTARTSERVICE_CALLED:wazuh-dashboard") > result.stdout.index(
            "CHANGEPASSWORDAPI_CALLED"
        )


class TestPasswordsMainSaveFailure:
    """A password applied but not saved in the credentials file ends in an error."""

    def test_exits_with_an_error_after_the_restarts(self):
        result = _run(
            "-u admin",
            extra_mocks={
                "passwords_saveIndexerCredentials": 'echo "SAVEINDEXERCREDENTIALS_CALLED"; save_failed=1',
                "passwords_changePassword": 'echo "CHANGEPASSWORD_CALLED"; restart_dashboard=1',
            },
            checkinstalled="indexer_installed=1",
        )
        assert result.returncode == 1
        assert "RESTARTSERVICE_CALLED:wazuh-dashboard" in result.stdout


class TestPasswordsMainSingleUserPath:
    """-u|--user with the password read from the standard input."""

    def _run_single_user(self):
        return _run("-u admin -p", checkinstalled="indexer_installed=1")

    def test_success_exit_code(self):
        assert_success(self._run_single_user())

    def test_takes_single_user_path(self):
        result = self._run_single_user()
        for marker in ("READPASSWORD_CALLED", "CHECKPASSWORD_CALLED:ValidPass1234", "READUSERS_CALLED",
                       "CHECKUSER_CALLED", "GETNETWORKHOST_CALLED", "GENERATEHASH_CALLED",
                       "CHANGEPASSWORD_CALLED", "RUNSECURITYADMIN_CALLED", "SAVEINDEXERCREDENTIALS_CALLED"):
            assert marker in result.stdout

    def test_password_is_read_and_checked_before_any_change(self):
        result = self._run_single_user()
        assert result.stdout.index("CHECKPASSWORD_CALLED") < result.stdout.index("READUSERS_CALLED")

    def test_does_not_take_batch_or_api_path(self):
        result = self._run_single_user()
        assert "GENERATEPASSWORDS_CALLED" not in result.stdout
        assert "CHANGEPASSWORDAPI_CALLED" not in result.stdout

    def test_does_not_autogenerate_password_when_provided(self):
        result = self._run_single_user()
        assert "GENERATEPASSWORD_CALLED" not in result.stdout

    def test_generates_password_without_p(self):
        result = _run("-u admin", checkinstalled="indexer_installed=1")
        assert_success(result)
        assert "GENERATEPASSWORD_CALLED" in result.stdout
        assert "READPASSWORD_CALLED" not in result.stdout


class TestPasswordsMainSingleApiUser:
    """-u with a Wazuh API user: passwords_checkUser flags it as an API user
    and only the API path runs."""

    def test_takes_only_the_api_path(self):
        result = _run(
            "-u wazuh-wui -p",
            extra_mocks={"passwords_checkUser": 'echo "CHECKUSER_CALLED"; api=1'},
            checkinstalled="indexer_installed=1; wazuh_installed=1",
        )
        assert_success(result)
        assert "CHANGEPASSWORDAPI_CALLED" in result.stdout
        assert "READUSERS_CALLED" not in result.stdout
        assert "RUNSECURITYADMIN_CALLED" not in result.stdout
