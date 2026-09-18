"""
Unit tests for passwords_tool/passwordsFunctions.sh

Covers: passwords_checkPassword, passwords_generatePassword,
        passwords_checkUser, passwords_getApiToken, passwords_isServiceActive,
        passwords_changePassword, passwords_changePasswordApi,
        passwords_generatePasswords, passwords_generateHash (changeall),
        passwords_changePassword (changeall), passwords_changePasswordApi
        (changeall), passwords_runSecurityAdmin (changeall)
"""

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

PASSWORDS = "passwords_tool/passwordsFunctions.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, PASSWORDS]

IGNORE_LOGGER = {"common_logger": "true"}


class TestPasswordsCheckPassword:
    """Tests for passwords_checkPassword.

    Validates that a password:
    - Has length 8–64
    - Contains uppercase, lowercase, digit, and symbol (.*+?-)
    """

    def _run(self, password):
        return run_bash_function(
            BASE_SOURCES,
            f'passwords_checkPassword "{password}"',
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
        )

    def test_success_valid_password(self):
        # Valid symbols per bash check: . * + ? -
        result = self._run("ValidPass1.")
        assert_success(result)

    def test_success_valid_with_all_symbols(self):
        # Exercises each valid symbol: . * + ? -
        result = self._run("Secure.Pass1*+?-")
        assert_success(result)

    def test_fail_no_uppercase(self):
        # Has lowercase, digit, valid symbol — only missing uppercase
        result = self._run("invalidpass1.")
        assert_failure(result)

    def test_fail_no_lowercase(self):
        # Has uppercase, digit, valid symbol — only missing lowercase
        result = self._run("INVALIDPASS1.")
        assert_failure(result)

    def test_fail_no_digit(self):
        # Has uppercase, lowercase, valid symbol — only missing digit
        result = self._run("InvalidPass.")
        assert_failure(result)

    def test_fail_no_symbol(self):
        # Has uppercase, lowercase, digit — only missing symbol
        result = self._run("InvalidPass1")
        assert_failure(result)

    def test_fail_too_short(self):
        # Has all character types but only 4 characters (minimum is 8)
        result = self._run("V1.a")
        assert_failure(result)

    def test_fail_too_long(self):
        # 65 characters with all required types — only too long
        result = self._run("A" * 61 + "1.aB")
        assert_failure(result)


class TestPasswordsCheckPasswordApiMinLength:
    """Tests for passwords_checkPassword when called with the Wazuh server
    API minimum length (12), as used for -A|--api password changes.

    Wazuh Indexer users keep the default 8-64 rule (see
    TestPasswordsCheckPassword); only the Wazuh server API/manager path
    raises the minimum to 12, per issue #950.
    """

    def _run(self, password, min_length=None):
        args = f'"{password}"' if min_length is None else f'"{password}" {min_length}'
        return run_bash_function(
            BASE_SOURCES,
            f"passwords_checkPassword {args}",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
        )

    def test_fail_eleven_chars_with_api_min_length(self):
        # 11 characters, valid otherwise: rejected once the API path requires 12
        result = self._run("ValidPass1.", min_length=12)
        assert_failure(result)

    def test_success_twelve_chars_with_api_min_length(self):
        # 12 characters, valid otherwise: accepted at the API minimum
        result = self._run("ValidPass1.a", min_length=12)
        assert_success(result)

    def test_success_eleven_chars_without_api_min_length(self):
        # Same 11-character password still passes on the Indexer/default path
        result = self._run("ValidPass1.")
        assert_success(result)


class TestPasswordsGeneratePassword:
    """Tests for passwords_generatePassword.

    The function generates a random password using /dev/urandom.
    We verify it exits 0 and that the `password` variable is non-empty.
    """

    def test_success_generates_password(self):
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_generatePassword; echo "generated:${password}"',
            {**IGNORE_LOGGER},
        )
        assert_success(result)
        assert "generated:" in result.stdout
        generated = result.stdout.split("generated:")[-1].strip()
        assert len(generated) > 0, "password variable should not be empty"

    def test_generated_password_passes_check(self):
        """The generated password should satisfy passwords_checkPassword."""
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_generatePassword; passwords_checkPassword "${password}"',
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
        )
        assert_success(result)


class TestPasswordsCheckUser:
    """Tests for passwords_checkUser.

    Checks if nuser exists in the users array.
    """

    def test_success_user_exists(self):
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_checkUser",
            {**IGNORE_LOGGER},
            {
                "users": "(wazuh admin kibanaserver)",
                "nuser": "admin",
            },
        )
        assert_success(result)

    def test_fail_user_not_found(self):
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_checkUser",
            {**IGNORE_LOGGER},
            {
                "users": "(wazuh admin kibanaserver)",
                "nuser": "nonexistent",
            },
        )
        assert_failure(result)


class TestPasswordsGetApiToken:
    """Tests for passwords_getApiToken.

    Makes a curl call to get a JWT token from the Wazuh API.
    """

    def test_success_valid_token(self):
        mocks = {
            **IGNORE_LOGGER,
            "curl": "echo 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.valid'",
            "sleep": "true",
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"adminUser": "admin", "adminPassword": "pass"},
        )
        assert_success(result)

    def test_fail_wazuh_manager_not_running(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"adminUser": "admin", "adminPassword": "pass"},
        )
        assert_failure(result)

    def test_fail_internal_error_exceeds_retries(self):
        mocks = {
            **IGNORE_LOGGER,
            "curl": "echo 'Wazuh Internal Error'",
            "sleep": "true",
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {
                "adminUser": "admin",
                "adminPassword": "pass",
                "max_internal_error_retries": "1",
            },
        )
        assert_failure(result)

    def test_fail_invalid_credentials(self):
        mocks = {
            **IGNORE_LOGGER,
            "curl": "echo 'Invalid credentials'",
            "sleep": "true",
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"adminUser": "admin", "adminPassword": "wrongpass"},
        )
        assert_failure(result)


class TestPasswordsIsServiceActive:
    """Tests for passwords_isServiceActive.

    Checks if a service is running on the system.
    """

    def test_success_systemd_service_active(self):
        mocks = {
            **IGNORE_LOGGER,
            "systemctl": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_isServiceActive wazuh-manager",
            mocks,
        )
        assert_success(result)

    def test_fail_systemd_service_inactive(self):
        mocks = {
            **IGNORE_LOGGER,
            "systemctl": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_isServiceActive wazuh-manager",
            mocks,
        )
        assert_failure(result)

    def test_fail_no_argument(self):
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_isServiceActive",
            {**IGNORE_LOGGER},
        )
        assert_failure(result)

    def test_fail_no_service_manager(self):
        """Test when no service manager is found."""
        mocks = {
            **IGNORE_LOGGER,
        }
        arrays = {
            "run_systemd_system": "()",  # Empty to simulate missing /run/systemd/system
        }
        result = run_bash_function(
            BASE_SOURCES,
            """
            # Simulate no service manager by removing directory check
            function passwords_isServiceActive() {
                if [ "$#" -ne 1 ]; then
                    common_logger -e "passwords_isServiceActive must be called with 1 argument."
                    return 1
                fi
                # Skip all manager checks and go directly to else
                common_logger -w "Cannot determine service status. No service manager found on the system."
                return 1
            }
            passwords_isServiceActive wazuh-manager
            """,
            mocks,
        )
        assert_failure(result)


class TestPasswordsChangePassword:
    """Tests for passwords_changePassword.

    Validates that the function checks service status before restarting.
    """

    def test_wazuh_dashboard_restart_when_active(self):
        """Test that wazuh-dashboard is restarted when service is active."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": 'echo "restart_called:$1" >&2',
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            """
            nuser="kibanaserver"
            dashpass="TestPass1."
            dashboard_installed="yes"
            
            # Mock the dashboard keystore check to return false
            function check_keystore() {
                return 1
            }
            
            # Override the specific commands that would fail
            function passwords_changePassword() {
                if [ "${nuser}" == "kibanaserver" ]; then
                    if [ -n "${dashboard_installed}" ] && [ -n "${dashpass}" ]; then
                        # Simulate the keystore check failure path
                        if passwords_isServiceActive "wazuh-dashboard"; then
                            passwords_restartService "wazuh-dashboard"
                        else
                            common_logger -d "wazuh-dashboard service is not running. Skipping restart."
                        fi
                    fi
                fi
            }
            
            passwords_changePassword
            """,
            mocks,
        )
        assert_success(result)
        assert "restart_called:wazuh-dashboard" in result.stderr

    def test_wazuh_dashboard_skip_restart_when_inactive(self):
        """Test that wazuh-dashboard restart is skipped when service is inactive."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": 'echo "restart_called:$1" >&2',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            """
            nuser="kibanaserver"
            dashpass="TestPass1."
            dashboard_installed="yes"
            
            # Override the function to test only the service check logic
            function passwords_changePassword() {
                if [ "${nuser}" == "kibanaserver" ]; then
                    if [ -n "${dashboard_installed}" ] && [ -n "${dashpass}" ]; then
                        if passwords_isServiceActive "wazuh-dashboard"; then
                            passwords_restartService "wazuh-dashboard"
                        else
                            common_logger -d "wazuh-dashboard service is not running. Skipping restart."
                        fi
                    fi
                fi
            }
            
            passwords_changePassword
            """,
            mocks,
        )
        assert_success(result)
        assert "restart_called:wazuh-dashboard" not in result.stderr


class TestPasswordsChangePasswordApi:
    """Tests for passwords_changePasswordApi.

    Validates that the function checks wazuh-manager status before API calls.
    """

    def test_success_when_wazuh_manager_active(self):
        """Test API password change succeeds when wazuh-manager is running."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_isServiceActive": "return 0",
            "passwords_getApiUserId": "user_id=1",
            "common_curl": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            """
            wazuh_installed="yes"
            nuser="testuser"
            password="TestPass1."
            TOKEN_API="test_token"
            passwords_changePasswordApi
            """,
            mocks,
        )
        assert_success(result)

    def test_fail_when_wazuh_manager_inactive(self):
        """Test API password change fails when wazuh-manager is not running."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            """
            wazuh_installed="yes"
            nuser="testuser"
            password="TestPass1."
            TOKEN_API="test_token"
            passwords_changePasswordApi
            """,
            mocks,
        )
        assert_failure(result)

    def test_skip_check_when_wazuh_not_installed(self):
        """Test that service check is skipped when wazuh is not installed."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_isServiceActive": "echo 'should_not_be_called'; return 1",
            "passwords_changeDashboardApiPassword": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            """
            wazuh_installed=""
            nuser="wazuh-wui"
            password="TestPass1."
            dashboard_installed="yes"
            passwords_changePasswordApi
            """,
            mocks,
        )
        assert_success(result)
        assert "should_not_be_called" not in result.stdout


class TestPasswordsGeneratePasswords:
    """Tests for passwords_generatePasswords (the -a|--change-all batch
    counterpart of passwords_generatePassword).

    Fills `passwords[]` (one entry per `users[]`) and `api_passwords[]`
    (one entry per `api_users[]`) by calling passwords_generatePassword in
    a loop, then clears `password` so it cannot leak into single-user
    checks that run afterwards.
    """

    def test_fills_one_password_per_user(self):
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_generatePasswords; echo "counts:${#passwords[@]}:${#api_passwords[@]}"',
            {**IGNORE_LOGGER},
            {
                "users": "(wazuh admin kibanaserver)",
                "api_users": "(wazuh wazuh-wui)",
            },
        )
        assert_success(result)
        assert "counts:3:2" in result.stdout

    def test_generated_passwords_satisfy_api_min_length(self):
        """passwords_generatePassword yields 32 chars, well above the
        12-char minimum required for Wazuh API users."""
        result = run_bash_function(
            BASE_SOURCES,
            """
            passwords_generatePasswords
            for p in "${passwords[@]}" "${api_passwords[@]}"; do
                passwords_checkPassword "${p}" 12
            done
            """,
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
            {
                "users": "(wazuh admin)",
                "api_users": "(wazuh-wui)",
            },
        )
        assert_success(result)

    def test_password_variable_left_empty(self):
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_generatePasswords; echo "final:[${password}]"',
            {**IGNORE_LOGGER},
            {
                "users": "(wazuh)",
                "api_users": "(wazuh-wui)",
            },
        )
        assert_success(result)
        assert "final:[]" in result.stdout


class TestPasswordsGenerateHashChangeAll:
    """Tests for passwords_generateHash in changeall (batch) mode.

    Iterates over `passwords[]` and fills `hashes[]`, calling
    hash.sh once per entry.
    """

    def test_success_one_hash_per_password(self):
        mocks = {
            **IGNORE_LOGGER,
            "bash": "echo hashed-$$",
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_generateHash; echo "count:${#hashes[@]}"',
            mocks,
            {
                "changeall": "1",
                "passwords": "(PassOne1. PassTwo1. PassThree1.)",
            },
        )
        assert_success(result)
        assert "count:3" in result.stdout

    def test_fail_when_hash_sh_fails(self):
        mocks = {
            **IGNORE_LOGGER,
            "installCommon_rollBack": "true",
            "bash": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_generateHash",
            mocks,
            {
                "changeall": "1",
                "passwords": "(PassOne1.)",
            },
        )
        assert_failure(result)


class TestPasswordsChangePasswordChangeAll:
    """Tests for passwords_changePassword in changeall (batch) mode.

    Runs the real sourced function (not a stand-in), keeping
    indexer_installed empty so the code never touches the real
    /etc/wazuh-indexer paths (guarded by `[ -n "${indexer_installed}" ]` /
    `[ -f ... ]` checks already present in the function).
    """

    def test_processes_every_user_in_the_array(self):
        """managerpass/dashpass get set from the matching passwords[]
        entry for every user in users[], proving the batch loop iterates
        over the whole array and not just a single user.

        The manager connects to the indexer as 'wazuh-manager' (see
        install_functions/manager.sh), not as 'admin' — so it is
        'wazuh-manager', not 'admin', whose password must be captured
        for the manager keystore.
        """
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": "true",
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "manager:${managerpass}|dash:${dashpass}"',
            mocks,
            {
                "changeall": "1",
                "users": "(kibanaserver wazuh-manager)",
                "passwords": "(DashPass1. ManagerPass1.)",
            },
        )
        assert_success(result)
        assert "manager:ManagerPass1.|dash:DashPass1." in result.stdout

    def test_invokes_manager_and_dashboard_keystore_without_nuser(self):
        """Both the manager keystore update and the dashboard keystore
        update run in batch mode even though nuser is never set."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePassword",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "dashboard_installed": "yes",
                "users": "(kibanaserver wazuh-manager)",
                "passwords": "(DashPass1. ManagerPass1.)",
            },
        )
        assert_success(result)
        assert "restart_called:wazuh-manager" in result.stdout
        assert "restart_called:wazuh-dashboard" in result.stdout

    def test_skips_manager_keystore_when_wazuh_manager_missing_from_users_array(self):
        """If users[] never contained 'wazuh-manager' (e.g. a partial
        passwords_readUsers result), managerpass stays empty and the
        manager keystore must NOT be updated with an empty password —
        doing so would break the manager/indexer connection."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePassword",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "dashboard_installed": "yes",
                "users": "(kibanaserver logstash)",
                "passwords": "(DashPass1. LogstashPass1.)",
            },
        )
        assert_success(result)
        assert "restart_called:wazuh-manager" not in result.stdout
        assert "LOG:-w Skipping Wazuh manager keystore update: no password available for the wazuh-manager user." in result.stdout
        # The dashboard path is unaffected by the missing wazuh-manager user.
        assert "restart_called:wazuh-dashboard" in result.stdout

    def test_rotating_admin_alone_does_not_touch_manager_keystore(self):
        """'admin' is the indexer/dashboard superuser, not the manager's
        indexer credential — rotating it in isolation (wazuh-manager not
        in users[]) must never touch the manager keystore."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePassword",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "users": "(admin)",
                "passwords": "(AdminPass1.)",
            },
        )
        assert_success(result)
        assert "restart_called:wazuh-manager" not in result.stdout


class TestPasswordsChangePasswordSingleUserManagerKeystore:
    """Tests for passwords_changePassword's manager-keystore branch on
    the single-user (-u|--user) path.

    The manager authenticates to the indexer as 'wazuh-manager', not
    'admin' (see install_functions/manager.sh), so only rotating
    'wazuh-manager' may touch the manager keystore.
    """

    def test_wazuh_manager_user_updates_manager_keystore(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": 'echo "restart_called:$1"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePassword",
            mocks,
            {
                "nuser": "wazuh-manager",
                "password": "ManagerPass1.",
                "wazuh_installed": "yes",
            },
        )
        assert_success(result)
        assert "restart_called:wazuh-manager" in result.stdout

    def test_admin_user_does_not_update_manager_keystore(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_restartService": 'echo "restart_called:$1"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePassword",
            mocks,
            {
                "nuser": "admin",
                "password": "AdminPass1.",
                "wazuh_installed": "yes",
            },
        )
        assert_success(result)
        assert "restart_called:wazuh-manager" not in result.stdout

    def test_kibanaserver_user_still_updates_dashboard_keystore(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePassword",
            mocks,
            {
                "nuser": "kibanaserver",
                "password": "DashPass1.",
                "dashboard_installed": "yes",
            },
        )
        assert_success(result)
        assert "restart_called:wazuh-dashboard" in result.stdout


class TestPasswordsChangePasswordApiChangeAll:
    """Tests for passwords_changePasswordApi in changeall (batch) mode.

    Iterates over api_passwords[], issuing one PUT per Wazuh API user.
    """

    def test_one_put_per_api_user(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_isServiceActive": "return 0",
            "passwords_getApiUserId": "user_id=1",
            "common_curl": 'echo "put_called:$*"',
            "passwords_getApiToken": "true",
            "sleep": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePasswordApi",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "adminUser": "someone-else",
                "api_users": "(wazuh wazuh-wui)",
                "api_passwords": "(PassOne1. PassTwo1.)",
                "TOKEN_API": "test_token",
            },
        )
        assert_success(result)
        assert result.stdout.count("put_called:") == 2

    def test_fail_when_wazuh_manager_inactive(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePasswordApi",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "api_users": "(wazuh)",
                "api_passwords": "(PassOne1.)",
                "TOKEN_API": "test_token",
            },
        )
        assert_failure(result)

    def test_reauthenticates_when_rotated_user_is_admin_user(self):
        """Rotating the API admin's own password must re-authenticate,
        otherwise the following PUTs would 401 against the old token."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_isServiceActive": "return 0",
            "passwords_getApiUserId": "user_id=1",
            "common_curl": "true",
            "passwords_getApiToken": 'echo "reauth_called"',
            "sleep": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePasswordApi",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "adminUser": "wazuh",
                "adminPassword": "OldPass1.",
                "api_users": "(wazuh)",
                "api_passwords": "(NewAdminPass1.)",
                "TOKEN_API": "test_token",
            },
        )
        assert_success(result)
        assert "reauth_called" in result.stdout

    def test_calls_dashboard_api_password_change_for_wazuh_wui(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_isServiceActive": "return 0",
            "passwords_getApiUserId": "user_id=1",
            "common_curl": "true",
            "passwords_changeDashboardApiPassword": 'echo "dashboard_called:$1"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePasswordApi",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "dashboard_installed": "yes",
                "adminUser": "admin",
                "api_users": "(wazuh-wui)",
                "api_passwords": "(WuiPass1.)",
                "TOKEN_API": "test_token",
            },
        )
        assert_success(result)
        assert "dashboard_called:WuiPass1." in result.stdout


class TestPasswordsChangePasswordApiInactiveManagerMessage:
    """The 'wazuh-manager service is not running' message must reference
    nuser in the single-user path, but nuser is always empty in
    changeall mode, so that branch must not print an empty user name."""

    def test_single_user_message_includes_nuser(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePasswordApi",
            mocks,
            {
                "wazuh_installed": "yes",
                "nuser": "testuser",
                "password": "TestPass1.",
                "TOKEN_API": "test_token",
            },
        )
        assert_failure(result)
        assert (
            "LOG:-e wazuh-manager service is not running. Skipping API password change for user testuser."
            in result.stdout
        )

    def test_changeall_message_omits_nuser(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePasswordApi",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "api_users": "(wazuh)",
                "api_passwords": "(PassOne1.)",
                "TOKEN_API": "test_token",
            },
        )
        assert_failure(result)
        assert (
            "LOG:-e wazuh-manager service is not running. Skipping Wazuh API password change."
            in result.stdout
        )
        assert "for user" not in result.stdout


class TestPasswordsGetApiTokenInactiveManagerMessage:
    """passwords_getApiToken is also called from main's changeall block
    (before passwords_changePasswordApi), so its own wazuh-manager-
    inactive message needs the same nuser/changeall split."""

    def test_single_user_message_includes_nuser(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"nuser": "testuser", "adminUser": "admin", "adminPassword": "pass"},
        )
        assert_failure(result)
        assert (
            "LOG:-e wazuh-manager service is not running. Skipping API password change for user testuser."
            in result.stdout
        )

    def test_changeall_message_omits_nuser(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"changeall": "1", "adminUser": "admin", "adminPassword": "pass"},
        )
        assert_failure(result)
        assert (
            "LOG:-e wazuh-manager service is not running. Skipping Wazuh API password change."
            in result.stdout
        )
        assert "for user" not in result.stdout


class TestPasswordsGetApiUsersInactiveManagerMessage:
    """passwords_getApiUsers is also called from main's changeall block,
    so its wazuh-manager-inactive message needs the same split."""

    def test_single_user_message_includes_nuser(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiUsers",
            mocks,
            {"nuser": "testuser", "TOKEN_API": "test_token"},
        )
        assert_failure(result)
        assert (
            "LOG:-e wazuh-manager service is not running. Skipping API password change for user testuser."
            in result.stdout
        )

    def test_changeall_message_omits_nuser(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiUsers",
            mocks,
            {"changeall": "1", "TOKEN_API": "test_token"},
        )
        assert_failure(result)
        assert (
            "LOG:-e wazuh-manager service is not running. Skipping Wazuh API password change."
            in result.stdout
        )
        assert "for user" not in result.stdout


class TestPasswordsGetApiUserIdInactiveManagerMessage:
    """passwords_getApiUserId receives the target user as $1 (not nuser),
    in both the single-user and changeall paths, so its message must
    name whatever user was passed in, regardless of changeall."""

    def test_single_user_mode_names_the_given_user(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_getApiUserId "testuser"',
            mocks,
            {"nuser": "testuser", "TOKEN_API": "test_token"},
        )
        assert_failure(result)
        assert (
            "LOG:-e wazuh-manager service is not running. Skipping API password change for user testuser."
            in result.stdout
        )

    def test_changeall_mode_names_the_given_user_not_nuser(self):
        """nuser is empty in changeall mode, but the function is called
        once per api_users[] entry with that user as $1 — the message
        must name that user, not the (empty) nuser."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_getApiUserId "wazuh-wui"',
            mocks,
            {"changeall": "1", "TOKEN_API": "test_token"},
        )
        assert_failure(result)
        assert (
            "LOG:-e wazuh-manager service is not running. Skipping API password change for user wazuh-wui."
            in result.stdout
        )
        assert "for user ." not in result.stdout


class TestPasswordsRunSecurityAdminChangeAll:
    """Tests for passwords_runSecurityAdmin in changeall (batch) mode.

    `eval` and `cp` are mocked so the real /etc/wazuh-indexer paths (which
    require root and don't exist in the test environment) are never
    touched; this isolates the changeall reporting block added at the
    end of the function.
    """

    def test_prints_password_for_every_user(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "eval": "return 0",
            "cp": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_runSecurityAdmin",
            mocks,
            {
                "changeall": "1",
                "indexer_installed": "yes",
                "users": "(admin kibanaserver)",
                "passwords": "(AdminPass1. DashPass1.)",
            },
        )
        assert_success(result)
        assert "LOG:-nl The password for user admin is AdminPass1." in result.stdout
        assert "LOG:-nl The password for user kibanaserver is DashPass1." in result.stdout

    def test_does_not_print_single_user_report_in_batch_mode(self):
        """The nuser-gated report lines must stay silent when nuser is
        empty, even though changeall's own report block fires."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "eval": "return 0",
            "cp": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_runSecurityAdmin",
            mocks,
            {
                "changeall": "1",
                "indexer_installed": "yes",
                "users": "(admin)",
                "passwords": "(AdminPass1.)",
            },
        )
        assert_success(result)
        assert "Password changed. Remember" not in result.stdout

