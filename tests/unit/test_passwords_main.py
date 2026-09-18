"""
Unit tests for passwords_tool/passwordsMain.sh

Covers: argument parsing and validation (mutual exclusions introduced by
-a|--change-all), and the two top-level flows driven by `main`:
- the -a|--change-all batch flow (indexer-only, and indexer+API)
- the pre-existing single-user (-u|--user) flow, which must keep working
  unmodified.

`common_checkRoot`, `common_checkSystem` and `common_checkInstalled` are
mocked so tests never depend on the real host (root permissions, package
manager, installed Wazuh components). The `passwords_*` functions that
would otherwise touch the real filesystem, systemd or the Wazuh API are
mocked to print a marker on stdout, so each test can assert exactly which
code path `main` took without executing any real system operation.
"""

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

COMMON_VARS = "common_functions/commonVariables.sh"
COMMON = "common_functions/common.sh"
PASSWORDS_VARS = "passwords_tool/passwordsVariables.sh"
PASSWORDS_FUNCTIONS = "passwords_tool/passwordsFunctions.sh"
PASSWORDS_MAIN = "passwords_tool/passwordsMain.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, PASSWORDS_VARS, PASSWORDS_FUNCTIONS, PASSWORDS_MAIN]

# Base mock set: silences/short-circuits everything main() can call so a
# test only has to override what it cares about (system checks + the
# installed-component flags). Every passwords_* mock announces itself on
# stdout so tests can assert exactly which functions ran.
BASE_MOCKS = {
    "common_checkRoot": "true",
    "common_checkSystem": "true",
    "passwords_readUsers": 'echo "READUSERS_CALLED"',
    "passwords_checkUser": 'echo "CHECKUSER_CALLED"',
    "passwords_getApiToken": 'echo "GETAPITOKEN_CALLED"',
    "passwords_getApiUsers": 'echo "GETAPIUSERS_CALLED"',
    "passwords_generatePassword": 'echo "GENERATEPASSWORD_CALLED"; password="AutoGenPass1."',
    "passwords_generatePasswords": 'echo "GENERATEPASSWORDS_CALLED"',
    "passwords_checkPassword": 'echo "CHECKPASSWORD_CALLED:$*"',
    "passwords_getNetworkHost": 'echo "GETNETWORKHOST_CALLED"',
    "passwords_generateHash": 'echo "GENERATEHASH_CALLED"',
    "passwords_changePassword": 'echo "CHANGEPASSWORD_CALLED"',
    "passwords_runSecurityAdmin": 'echo "RUNSECURITYADMIN_CALLED"',
    "passwords_isServiceActive": 'echo "ISSERVICEACTIVE_CALLED:$*"; return 0',
    "passwords_changePasswordApi": 'echo "CHANGEPASSWORDAPI_CALLED"',
    "passwords_restartService": 'echo "RESTARTSERVICE_CALLED:$1"',
}


def _run(args, extra_mocks=None, checkinstalled="true"):
    mocks = {
        **BASE_MOCKS,
        "common_checkInstalled": checkinstalled,
        **(extra_mocks or {}),
    }
    return run_bash_function(BASE_SOURCES, f"main {args}", mocks)


class TestPasswordsMainMutualExclusions:
    """Argument validation added/relaxed for -a|--change-all.

    Each case changes exactly one condition away from a valid baseline
    (a valid -a/-au/-ap combo, or a valid -u/-p combo), so a passing test
    can only be explained by the specific validation under test.
    """

    def test_fail_no_user_and_no_changeall(self):
        # Baseline would be "-u admin" or "-a"; neither is given.
        result = _run("-v")
        assert_failure(result)

    def test_fail_changeall_with_user(self):
        # Baseline: "-a" alone. Adding -u must be rejected.
        result = _run("-a -u admin")
        assert_failure(result)

    def test_fail_changeall_with_password(self):
        # Baseline: "-a" alone. Adding -p must be rejected.
        result = _run("-a -p ValidPass1.")
        assert_failure(result)

    def test_fail_changeall_with_api_flag(self):
        # Baseline: "-a" alone. Adding -A must be rejected (-a already
        # rotates API passwords when -au/-ap are given).
        result = _run("-a -A")
        assert_failure(result)

    def test_fail_admin_user_without_admin_password(self):
        # Baseline: "-a -au admin -ap AdminPass1.". Dropping -ap must be
        # rejected. -a is kept so the earlier "-u xor -a" check does not
        # also fire, isolating this one condition.
        result = _run("-a -au admin")
        assert_failure(result)

    def test_fail_admin_password_without_admin_user(self):
        # Baseline: "-a -au admin -ap AdminPass1.". Dropping -au must be
        # rejected.
        result = _run("-a -ap AdminPass1.")
        assert_failure(result)

    def test_success_single_user_baseline_still_works(self):
        # Sanity check for the baseline itself used above.
        result = _run("-u admin -p ValidPass1.", checkinstalled="indexer_installed=1")
        assert_success(result)


class TestPasswordsMainChangeAllWithoutAdminCredentials:
    """-a|--change-all with no -au/-ap: only the indexer batch path runs."""

    def _run_no_creds(self):
        return _run("-a", checkinstalled="indexer_installed=1")

    def test_success_exit_code(self):
        assert_success(self._run_no_creds())

    def test_takes_indexer_batch_path(self):
        result = self._run_no_creds()
        assert "READUSERS_CALLED" in result.stdout
        assert "GENERATEPASSWORDS_CALLED" in result.stdout
        assert "GETNETWORKHOST_CALLED" in result.stdout
        assert "GENERATEHASH_CALLED" in result.stdout
        assert "CHANGEPASSWORD_CALLED" in result.stdout
        assert "RUNSECURITYADMIN_CALLED" in result.stdout

    def test_does_not_take_api_path(self):
        result = self._run_no_creds()
        assert "GETAPITOKEN_CALLED" not in result.stdout
        assert "GETAPIUSERS_CALLED" not in result.stdout
        assert "CHANGEPASSWORDAPI_CALLED" not in result.stdout

    def test_logs_api_credentials_not_provided_warning(self):
        result = self._run_no_creds()
        assert "Wazuh API admin credentials not provided, Wazuh API passwords not changed." in result.stdout


class TestPasswordsMainChangeAllWithAdminCredentials:
    """-a|--change-all with -au/-ap: both the indexer and API paths run."""

    def _run_with_creds(self):
        return _run(
            "-a -au admin -ap AdminPass1.",
            checkinstalled="indexer_installed=1; wazuh_installed=1; dashboard_installed=1",
        )

    def test_success_exit_code(self):
        assert_success(self._run_with_creds())

    def test_takes_indexer_batch_path(self):
        result = self._run_with_creds()
        assert "READUSERS_CALLED" in result.stdout
        assert "GENERATEPASSWORDS_CALLED" in result.stdout
        assert "GETNETWORKHOST_CALLED" in result.stdout
        assert "GENERATEHASH_CALLED" in result.stdout
        assert "CHANGEPASSWORD_CALLED" in result.stdout
        assert "RUNSECURITYADMIN_CALLED" in result.stdout

    def test_takes_api_path(self):
        result = self._run_with_creds()
        assert "GETAPITOKEN_CALLED" in result.stdout
        assert "GETAPIUSERS_CALLED" in result.stdout
        assert "ISSERVICEACTIVE_CALLED:wazuh-manager" in result.stdout
        assert "CHANGEPASSWORDAPI_CALLED" in result.stdout

    def test_restarts_manager_and_dashboard(self):
        result = self._run_with_creds()
        assert "RESTARTSERVICE_CALLED:wazuh-manager" in result.stdout
        assert "RESTARTSERVICE_CALLED:wazuh-dashboard" in result.stdout


class TestPasswordsMainSingleUserPath:
    """-u|--user keeps working exactly as before -a|--change-all was added."""

    def _run_single_user(self):
        return _run("-u admin -p ValidPass1.", checkinstalled="indexer_installed=1")

    def test_success_exit_code(self):
        assert_success(self._run_single_user())

    def test_takes_single_user_path(self):
        result = self._run_single_user()
        assert "READUSERS_CALLED" in result.stdout
        assert "CHECKUSER_CALLED" in result.stdout
        assert "CHECKPASSWORD_CALLED:ValidPass1." in result.stdout
        assert "GETNETWORKHOST_CALLED" in result.stdout
        assert "GENERATEHASH_CALLED" in result.stdout
        assert "CHANGEPASSWORD_CALLED" in result.stdout
        assert "RUNSECURITYADMIN_CALLED" in result.stdout

    def test_does_not_take_batch_or_api_path(self):
        result = self._run_single_user()
        assert "GENERATEPASSWORDS_CALLED" not in result.stdout
        assert "GETAPITOKEN_CALLED" not in result.stdout
        assert "GETAPIUSERS_CALLED" not in result.stdout
        assert "CHANGEPASSWORDAPI_CALLED" not in result.stdout

    def test_does_not_autogenerate_password_when_provided(self):
        result = self._run_single_user()
        assert "GENERATEPASSWORD_CALLED" not in result.stdout


class TestPasswordsMainWazuhManagerInactiveMessage:
    """main's own wazuh-manager-inactive guard (shared between -A and -a)
    must keep naming nuser for a single-user API change, but must not
    print an empty user name in --change-all mode, where nuser is
    always empty."""

    def test_single_user_message_includes_nuser(self):
        result = _run(
            "-u wazuh-wui -p ValidPass1. -A -au admin -ap AdminPass1.",
            extra_mocks={"passwords_isServiceActive": "return 1"},
        )
        assert_failure(result)
        assert "Skipping API password change for user wazuh-wui." in result.stdout

    def test_changeall_message_omits_nuser(self):
        result = _run(
            "-a -au admin -ap AdminPass1.",
            extra_mocks={"passwords_isServiceActive": "return 1"},
            checkinstalled="indexer_installed=1",
        )
        assert_failure(result)
        assert "Skipping Wazuh API password change." in result.stdout
        assert "for user" not in result.stdout
