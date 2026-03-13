"""
Unit tests for passwords_tool/passwordsFunctions.sh

Covers: passwords_checkPassword, passwords_generatePassword,
        passwords_checkUser, passwords_getApiToken
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
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"adminUser": "admin", "adminPassword": "pass"},
        )
        assert_success(result)

    def test_fail_internal_error_exceeds_retries(self):
        mocks = {
            **IGNORE_LOGGER,
            "curl": "echo 'Wazuh Internal Error'",
            "sleep": "true",
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
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_getApiToken",
            mocks,
            {"adminUser": "admin", "adminPassword": "wrongpass"},
        )
        assert_failure(result)
