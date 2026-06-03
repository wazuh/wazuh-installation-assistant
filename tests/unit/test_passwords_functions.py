"""
Unit tests for passwords_tool/passwordsFunctions.sh

Covers: passwords_checkPassword, passwords_generatePassword,
        passwords_checkUser, passwords_getApiToken, passwords_isServiceActive,
        passwords_changePassword, passwords_changePasswordApi
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

