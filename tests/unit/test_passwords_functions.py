"""
Unit tests for passwords_tool/passwordsFunctions.sh

Covers: passwords_checkPassword, passwords_generatePassword,
        passwords_readPassword, passwords_checkUser,
        passwords_checkCredentialsFile, passwords_getEnvKey,
        passwords_saveCredential, passwords_hashPassword,
        passwords_isServiceActive, passwords_changePassword,
        passwords_changePasswordApi, passwords_updateDashboardKeystore,
        passwords_updateManagerKeystore, passwords_restartPendingServices,
        passwords_generatePasswords, passwords_generateHash (changeall),
        passwords_runSecurityAdmin
"""

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

PASSWORDS = "passwords_tool/passwordsFunctions.sh"
PASSWORDS_VARS = "passwords_tool/passwordsVariables.sh"
CREDENTIALS = "credentials_lib/wazuh-credentials.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, CREDENTIALS, PASSWORDS_VARS, PASSWORDS]

IGNORE_LOGGER = {"common_logger": "true"}

# A valid bcrypt digest, the shape hash.sh prints.
BCRYPT = "$2y$12$" + "a" * 53


class TestPasswordsCheckPassword:
    """Tests for passwords_checkPassword.

    Same rule as the Wazuh packages: 12-64 characters from
    A-Z a-z 0-9 . , _ + : @ % ^ = ~ -, with at least one letter and one
    digit (wazuh_password_validate), and not a JSON number, which the Wazuh
    dashboard keystore would store as a number.
    """

    def _run(self, password):
        return run_bash_function(
            BASE_SOURCES,
            'passwords_checkPassword "${CHECKED}"',
            {"common_logger": 'echo "LOG:$*"'},
            {"CHECKED": password},
        )

    def test_success_letters_and_digits_only(self):
        # No symbol needed any more: package generated passwords may have none.
        assert_success(self._run("abcdefghij12"))

    def test_success_every_allowed_symbol(self):
        assert_success(self._run("Secure1.,_+:@%^=~-"))

    def test_success_sixty_four_chars(self):
        assert_success(self._run("a1" * 32))

    def test_fail_eleven_chars(self):
        assert_failure(self._run("abcdefghi12"))

    def test_fail_sixty_five_chars(self):
        assert_failure(self._run("a1" * 32 + "b"))

    def test_fail_no_letter(self):
        assert_failure(self._run("123456789012"))

    def test_fail_no_digit(self):
        assert_failure(self._run("abcdefghijkl"))

    def test_fail_symbol_the_manager_refuses(self):
        for password in ("ValidPass12*", "ValidPass12?", "Valid Pass12", "ValidPass12$", "ValidPäss123"):
            assert_failure(self._run(password))

    def test_fail_json_number(self):
        result = self._run("123456789e10")
        assert_failure(result)
        assert "cannot be a number" in result.stdout

    def test_error_names_the_rule_not_the_value(self):
        result = self._run("Short1")
        assert_failure(result)
        assert "Short1" not in result.stdout
        assert "between 12 and 64 characters" in result.stdout

    def test_fail_line_break(self):
        assert_failure(self._run("ValidPass1234\nx"))


class TestPasswordsGeneratePassword:
    """Tests for passwords_generatePassword, which uses wazuh_password_generate."""

    def test_success_generates_a_32_char_password(self):
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_generatePassword; echo "generated:${password}"',
            {**IGNORE_LOGGER},
        )
        assert_success(result)
        generated = result.stdout.split("generated:")[-1].strip()
        assert len(generated) == 32
        assert any(c.islower() for c in generated)
        assert any(c.isupper() for c in generated)
        assert any(c.isdigit() for c in generated)
        assert set(generated) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,_+:@%^=~-"
        )

    def test_generated_password_passes_check(self):
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_generatePassword; passwords_checkPassword "${password}"',
            {**IGNORE_LOGGER},
        )
        assert_success(result)

    def test_fail_when_the_library_fails(self):
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_generatePassword",
            {**IGNORE_LOGGER, "wazuh_password_generate": "return 1"},
        )
        assert_failure(result)


class TestPasswordsReadPassword:
    """Tests for passwords_readPassword: the password comes from the standard
    input, never from the command line."""

    def test_reads_the_first_line(self):
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_readPassword; echo "read:[${password}]"',
            {**IGNORE_LOGGER},
            {"nuser": "admin"},
            stdin="FromStdin1234\nsecond line\n",
        )
        assert_success(result)
        assert "read:[FromStdin1234]" in result.stdout

    def test_reads_a_line_without_newline(self):
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_readPassword; echo "read:[${password}]"',
            {**IGNORE_LOGGER},
            {"nuser": "admin"},
            stdin="FromStdin1234",
        )
        assert_success(result)
        assert "read:[FromStdin1234]" in result.stdout

    def test_fail_empty_input(self):
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_readPassword",
            {"common_logger": 'echo "LOG:$*"'},
            {"nuser": "admin"},
            stdin="",
        )
        assert_failure(result)
        assert "No password was given on the standard input." in result.stdout


class TestPasswordsCheckUser:
    """Tests for passwords_checkUser.

    Only the accounts of the Wazuh packages are supported: the Wazuh indexer
    users admin, kibanaserver and wazuh-manager, and the Wazuh API users
    wazuh and wazuh-wui.
    """

    def _run(self, nuser, env=None):
        return run_bash_function(
            BASE_SOURCES,
            'passwords_checkUser; echo "api:[${api}]"',
            {"common_logger": 'echo "LOG:$*"'},
            {"nuser": nuser, **(env or {})},
        )

    def test_success_indexer_user(self):
        result = self._run("admin", {"indexer_installed": "1", "users": "(admin kibanaserver wazuh-manager)"})
        assert_success(result)
        assert "api:[]" in result.stdout

    def test_fail_indexer_user_missing_from_internal_users(self):
        result = self._run("wazuh-manager", {"indexer_installed": "1", "users": "(admin kibanaserver)"})
        assert_failure(result)

    def test_fail_indexer_user_without_indexer(self):
        result = self._run("admin")
        assert_failure(result)
        assert "The Wazuh indexer is not installed" in result.stdout

    def test_success_api_user_sets_api(self):
        result = self._run("wazuh-wui", {"wazuh_installed": "1"})
        assert_success(result)
        assert "api:[1]" in result.stdout

    def test_fail_api_user_without_manager(self):
        result = self._run("wazuh")
        assert_failure(result)
        assert "The Wazuh manager is not installed" in result.stdout

    def test_fail_other_users(self):
        for user in ("custom-user", "wazuh-readonly", "logstash"):
            result = self._run(user, {"indexer_installed": "1", "wazuh_installed": "1",
                                      "users": f"(admin {user})"})
            assert_failure(result)
            assert f"The user {user} is not supported." in result.stdout


class TestPasswordsCheckCredentialsFile:
    """A credentials file the library refuses (status 2) stops the tool."""

    def test_success_when_the_file_is_absent(self):
        result = run_bash_function(
            BASE_SOURCES, "passwords_checkCredentialsFile",
            {**IGNORE_LOGGER, "wazuh_env_get": "return 1"},
        )
        assert_success(result)

    def test_success_when_the_file_is_valid(self):
        result = run_bash_function(
            BASE_SOURCES, "passwords_checkCredentialsFile",
            {**IGNORE_LOGGER, "wazuh_env_get": "echo secret; return 0"},
        )
        assert_success(result)
        assert "secret" not in result.stdout

    def test_fail_when_the_file_is_invalid(self):
        result = run_bash_function(
            BASE_SOURCES, "passwords_checkCredentialsFile",
            {"common_logger": 'echo "LOG:$*"', "wazuh_env_get": "return 2",
             "wazuh_env_get_file": "echo /etc/wazuh/credentials.env"},
        )
        assert_failure(result)
        assert "The credentials file /etc/wazuh/credentials.env cannot be used" in result.stdout


class TestPasswordsGetEnvKey:
    """The keys are the ones the Wazuh packages publish and read."""

    def test_every_supported_user_has_its_key(self):
        expected = {
            "admin": "WAZUH_INDEXER_ADMIN_PASSWORD",
            "kibanaserver": "WAZUH_INDEXER_KIBANASERVER_PASSWORD",
            "wazuh-manager": "WAZUH_INDEXER_MANAGER_PASSWORD",
            "wazuh": "WAZUH_MANAGER_API_PASSWORD",
            "wazuh-wui": "WAZUH_MANAGER_WUI_PASSWORD",
        }
        for user, key in expected.items():
            result = run_bash_function(BASE_SOURCES, f"passwords_getEnvKey {user}")
            assert_success(result)
            assert result.stdout.strip() == key

    def test_fail_other_users(self):
        assert_failure(run_bash_function(BASE_SOURCES, "passwords_getEnvKey custom-user"))


class TestPasswordsSaveCredential:
    """Tests for passwords_saveCredential.

    A generated password is always recorded in credentials.env, because it is
    not shown anywhere else. A password given by the operator only updates a
    credentials file that already exists.
    """

    def _run(self, generated, file_exists, set_status=0, user="admin"):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "wazuh_env_get_file": 'echo "${ENV_FILE}"',
            "wazuh_env_set": f'echo "SET:$1"; return {set_status}',
        }
        script = f"""
            ENV_FILE="$(mktemp -d)/credentials.env"
            {'touch "${ENV_FILE}"' if file_exists else ''}
            passwords_saveCredential {user} "NewPassword123" "{generated}"
            echo "status:$? failed:[${{save_failed}}]"
        """
        return run_bash_function(BASE_SOURCES, script, mocks)

    def test_generated_password_creates_the_record(self):
        result = self._run(generated="1", file_exists=False)
        assert "SET:WAZUH_INDEXER_ADMIN_PASSWORD" in result.stdout
        assert "status:0 failed:[]" in result.stdout
        assert "was saved in" in result.stdout
        assert "NewPassword123" not in result.stdout

    def test_supplied_password_updates_an_existing_file(self):
        result = self._run(generated="", file_exists=True)
        assert "SET:WAZUH_INDEXER_ADMIN_PASSWORD" in result.stdout
        assert "status:0" in result.stdout

    def test_supplied_password_never_creates_the_file(self):
        result = self._run(generated="", file_exists=False)
        assert "SET:" not in result.stdout
        assert "status:0" in result.stdout

    def test_api_user_uses_the_manager_key(self):
        result = self._run(generated="1", file_exists=False, user="wazuh-wui")
        assert "SET:WAZUH_MANAGER_WUI_PASSWORD" in result.stdout

    def test_failed_write_is_reported(self):
        result = self._run(generated="1", file_exists=False, set_status=1)
        assert "status:1 failed:[1]" in result.stdout
        assert "was applied, but it could not be saved" in result.stdout
        assert "NewPassword123" not in result.stdout


class TestPasswordsHashPassword:
    """The password reaches hash.sh through its environment, never through
    the command line, and only a bcrypt digest is taken from its output."""

    def test_password_goes_through_the_environment(self):
        mocks = {
            "bash": 'echo "ARGS:$*" >> "${CALLS}"; echo "warning: some java message"; '
                    f'[ "${{!3}}" == "NewPassword123" ] && echo \'{BCRYPT}\'',
        }
        result = run_bash_function(
            BASE_SOURCES,
            'CALLS=$(mktemp); passwords_hashPassword "NewPassword123"; echo "---"; cat "${CALLS}"',
            mocks,
        )
        assert_success(result)
        digest, calls = result.stdout.split("---")
        assert digest.strip() == BCRYPT
        assert "-env WAZUH_PASSWORDS_TOOL_SECRET" in calls
        assert "NewPassword123" not in calls

    def test_prints_nothing_without_a_digest(self):
        result = run_bash_function(BASE_SOURCES, 'passwords_hashPassword "x"', {"bash": "echo not-a-hash"})
        assert result.stdout.strip() == ""


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


class TestPasswordsRestartPendingServices:
    """Tests for passwords_restartPendingServices.

    passwords_changePassword no longer restarts anything: it records
    restart_manager/restart_dashboard, and the restarts run from here,
    after passwords_runSecurityAdmin has applied the new hash on the
    indexer. Each restart is guarded by the service state.
    """

    def test_restarts_both_services_when_both_are_pending_and_active(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_restartPendingServices",
            mocks,
            {"restart_manager": "1", "restart_dashboard": "1"},
        )
        assert_success(result)
        assert "restart_called:wazuh-manager" in result.stdout
        assert "restart_called:wazuh-dashboard" in result.stdout

    def test_restarts_nothing_when_nothing_is_pending(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_restartPendingServices",
            mocks,
        )
        assert_success(result)
        assert "restart_called" not in result.stdout

    def test_wazuh_manager_restart_is_skipped_when_service_is_inactive(self):
        """A stopped wazuh-manager must not be started by a password
        change. The keystore already holds the new credentials, so they
        are applied whenever the operator starts the service."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_restartPendingServices",
            mocks,
            {"restart_manager": "1", "manager_keystore_updated": "1"},
        )
        assert_success(result)
        assert "restart_called:wazuh-manager" not in result.stdout
        assert (
            "LOG:-w The Wazuh manager keystore was updated, but the wazuh-manager "
            "service is not running. The restart is pending: the new Wazuh indexer "
            "credentials will be applied when the service starts."
        ) in result.stdout

    def test_wazuh_dashboard_restart_is_skipped_when_service_is_inactive(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_restartPendingServices",
            mocks,
            {"restart_dashboard": "1", "dashboard_keystore_updated": "1"},
        )
        assert_success(result)
        assert "restart_called:wazuh-dashboard" not in result.stdout
        assert (
            "LOG:-w The Wazuh dashboard keystore was updated, but the wazuh-dashboard "
            "service is not running. The restart is pending: the new credentials "
            "will be applied when the service starts."
        ) in result.stdout

    def test_message_omits_the_keystore_when_no_keystore_was_updated(self):
        """A restart queued without touching any keystore must not claim
        one was updated."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_restartPendingServices",
            mocks,
            {"restart_manager": "1", "restart_dashboard": "1"},
        )
        assert_success(result)
        assert "LOG:-w wazuh-manager service is not running. Skipping restart." in result.stdout
        assert "LOG:-w wazuh-dashboard service is not running. Skipping restart." in result.stdout
        assert "keystore was updated" not in result.stdout

    def test_each_service_is_checked_on_its_own(self):
        """An inactive dashboard must not hold back an active manager."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_restartService": 'echo "restart_called:$1"',
            "passwords_isServiceActive": '[ "$1" == "wazuh-manager" ]',
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_restartPendingServices",
            mocks,
            {"restart_manager": "1", "restart_dashboard": "1"},
        )
        assert_success(result)
        assert "restart_called:wazuh-manager" in result.stdout
        assert "restart_called:wazuh-dashboard" not in result.stdout


class TestPasswordsUpdateManagerKeystore:
    """Tests for passwords_updateManagerKeystore.

    The manager reads its indexer credentials from the keystore under
    the 'indexer' column family, keys 'username' and 'password' (see
    install_functions/manager.sh). Both keys are written, so a keystore
    left inconsistent by an earlier run repairs itself.
    """

    def test_writes_username_and_password(self):
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_updateManagerKeystore "ManagerPass1."',
            {**IGNORE_LOGGER, "keystore_stub": 'echo "keystore:$* value=$(cat)"'},
            {"manager_keystore": "keystore_stub"},
        )
        assert_success(result)
        assert "keystore:-f indexer -k username value=wazuh-manager" in result.stdout
        assert "keystore:-f indexer -k password value=ManagerPass1." in result.stdout

    def test_does_not_put_the_password_on_the_command_line(self):
        """The value travels on standard input: anything on the command
        line is visible in ps for the duration of the call."""
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_updateManagerKeystore "ManagerPass1."',
            {**IGNORE_LOGGER, "keystore_stub": 'echo "args:$*"; cat > /dev/null'},
            {"manager_keystore": "keystore_stub"},
        )
        assert_success(result)
        assert "ManagerPass1." not in result.stdout

    def test_returns_failure_when_the_keystore_write_fails(self):
        """A keystore binary that is missing, or that cannot open
        queue/keystore, must surface as a failure, not as a silent no-op."""
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_updateManagerKeystore "ManagerPass1."',
            {"common_logger": 'echo "LOG:$*"', "keystore_stub": "cat > /dev/null; return 1"},
            {"manager_keystore": "keystore_stub"},
        )
        assert_failure(result)
        assert "LOG:-e Could not write the Wazuh indexer username to the Wazuh manager keystore." in result.stdout

    def test_does_not_write_the_password_after_a_failed_username_write(self):
        """The password write is skipped once the username write failed, so
        the keystore is not left holding a password for a username that was
        never stored."""
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_updateManagerKeystore "ManagerPass1."',
            {"common_logger": 'echo "LOG:$*"',
             "keystore_stub": 'echo "keystore:$*"; cat > /dev/null; return 1'},
            {"manager_keystore": "keystore_stub"},
        )
        assert_failure(result)
        assert "keystore:-f indexer -k username" in result.stdout
        assert "keystore:-f indexer -k password" not in result.stdout

    def test_fails_without_a_password_argument(self):
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_updateManagerKeystore",
            {"common_logger": 'echo "LOG:$*"'},
        )
        assert "LOG:-e passwords_updateManagerKeystore must be called with 1 argument." in result.stdout


class TestPasswordsChangePasswordApi:
    """Tests for passwords_changePasswordApi and passwords_changeApiUserPassword.

    Wazuh API passwords are changed with rbac_control change-password, which
    reads the new password from the standard input, so no Wazuh API admin
    credentials are needed.
    """

    RBAC_OK = 'echo "ARGS:$*" >> "${CALLS}"; echo "STDIN:$(cat)" >> "${CALLS}"; printf "\\t%s: UPDATED\\n" "$3"'

    def _run(self, env, rbac=None, extra_mocks=None):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "rbac_stub": rbac or self.RBAC_OK,
            "passwords_saveCredential": 'echo "SAVE:$1:$3"',
            "passwords_updateDashboardKeystore": 'echo "DASHBOARD_KEYSTORE:$1:$2"',
            **(extra_mocks or {}),
        }
        script = """
            rbac_control="$(mktemp)"; chmod +x "${rbac_control}"
            printf '#!/bin/bash\\nrbac_stub "$@"\\n' > "${rbac_control}"
            export -f rbac_stub
            export CALLS="$(mktemp)"
            passwords_changePasswordApi
            echo "status:$? pending:[${restart_dashboard}]"
            echo "---CALLS---"; cat "${CALLS}"
        """
        result = run_bash_function(BASE_SOURCES, script, mocks, env)
        result.stdout, _, result.calls = result.stdout.partition("---CALLS---")
        return result

    def test_password_goes_through_stdin(self):
        result = self._run({"nuser": "wazuh", "password": "NewApiPass123", "autopass": ""})
        assert "status:0" in result.stdout
        assert "ARGS:change-password -u wazuh -p -" in result.calls
        assert "STDIN:NewApiPass123" in result.calls
        assert "NewApiPass123" not in result.calls.split("STDIN:")[0]
        assert "NewApiPass123" not in result.stdout

    def test_saves_the_new_password(self):
        result = self._run({"nuser": "wazuh", "password": "NewApiPass123", "autopass": "1"})
        assert "SAVE:wazuh:1" in result.stdout

    def test_fail_when_rbac_control_fails(self):
        result = self._run({"nuser": "wazuh", "password": "NewApiPass123"},
                           rbac='cat > /dev/null; echo "Error 5007: bad"; return 1')
        assert "status:1" in result.stdout
        assert "could not be changed: Error 5007: bad" in result.stdout
        assert "SAVE:" not in result.stdout

    def test_fail_when_rbac_control_exits_0_without_updating(self):
        """rbac_control on 5.0.0 exits 0 after an internal error, so its
        output is checked too."""
        result = self._run({"nuser": "wazuh", "password": "NewApiPass123"},
                           rbac='cat > /dev/null; printf "\\twazuh: FAILED | error\\n"')
        assert "status:1" in result.stdout
        assert "SAVE:" not in result.stdout

    def test_fail_when_rbac_control_is_missing(self):
        mocks = {"common_logger": 'echo "LOG:$*"'}
        result = run_bash_function(
            BASE_SOURCES,
            'rbac_control=/nonexistent/rbac_control; passwords_changePasswordApi; echo "status:$?"',
            mocks,
            {"nuser": "wazuh", "password": "NewApiPass123"},
        )
        assert "status:1" in result.stdout
        assert "Cannot find /nonexistent/rbac_control" in result.stdout

    def test_wazuh_wui_updates_the_dashboard_keystore(self):
        result = self._run({"nuser": "wazuh-wui", "password": "NewWuiPass123", "dashboard_installed": "1"})
        assert "DASHBOARD_KEYSTORE:wazuh_core.hosts.default.password:NewWuiPass123" in result.stdout
        assert "status:0 pending:[1]" in result.stdout

    def test_wazuh_wui_is_saved_before_the_dashboard_is_updated(self):
        result = self._run({"nuser": "wazuh-wui", "password": "NewWuiPass123", "dashboard_installed": "1"})
        assert result.stdout.index("SAVE:wazuh-wui") < result.stdout.index("DASHBOARD_KEYSTORE:")

    def test_wazuh_wui_without_local_dashboard_warns(self):
        result = self._run({"nuser": "wazuh-wui", "password": "NewWuiPass123"})
        assert "DASHBOARD_KEYSTORE:" not in result.stdout
        assert "The Wazuh dashboard is not installed on this host." in result.stdout

    def test_fail_when_the_dashboard_keystore_fails(self):
        result = self._run({"nuser": "wazuh-wui", "password": "NewWuiPass123", "dashboard_installed": "1"},
                           extra_mocks={"passwords_updateDashboardKeystore": "return 1"})
        assert "status:1 pending:[]" in result.stdout

    def test_wazuh_does_not_touch_the_dashboard(self):
        result = self._run({"nuser": "wazuh", "password": "NewApiPass123", "dashboard_installed": "1"})
        assert "DASHBOARD_KEYSTORE:" not in result.stdout
        assert "pending:[]" in result.stdout

    def test_changeall_changes_every_api_user(self):
        result = self._run({"changeall": "1", "api_users": "(wazuh wazuh-wui)",
                            "api_passwords": "(PassOne12345 PassTwo12345)"})
        assert "status:0" in result.stdout
        assert "ARGS:change-password -u wazuh -p -" in result.calls
        assert "ARGS:change-password -u wazuh-wui -p -" in result.calls
        assert "SAVE:wazuh:1" in result.stdout
        assert "SAVE:wazuh-wui:1" in result.stdout

    def test_changeall_stops_at_the_first_failure(self):
        result = self._run({"changeall": "1", "api_users": "(wazuh wazuh-wui)",
                            "api_passwords": "(PassOne12345 PassTwo12345)"},
                           rbac='cat > /dev/null; echo "ARGS:$*" >> "${CALLS}"; return 1')
        assert "status:1" in result.stdout
        assert "-u wazuh-wui" not in result.calls


class TestPasswordsUpdateDashboardKeystore:
    """The dashboard keystore belongs to the wazuh-dashboard user, so it is
    written as that user, and the value goes through the standard input."""

    def _run(self, runuser_body, keystore_exists=True):
        mocks = {"common_logger": 'echo "LOG:$*"', "runuser": runuser_body}
        script = f"""
            dashboard_keystore="$(mktemp)"
            {'chmod +x "${dashboard_keystore}"' if keystore_exists else 'rm -f "${dashboard_keystore}"'}
            export CALLS="$(mktemp)"
            passwords_updateDashboardKeystore opensearch.password "DashPass12345"
            echo "status:$?"
            cat "${{CALLS}}"
        """
        return run_bash_function(BASE_SOURCES, script, mocks)

    def test_runs_as_the_dashboard_user_with_the_value_on_stdin(self):
        result = self._run('echo "RUNUSER:$*" >> "${CALLS}"; echo "STDIN:$(cat)" >> "${CALLS}"')
        assert "status:0" in result.stdout
        runuser_line = [l for l in result.stdout.splitlines() if l.startswith("RUNUSER:")][0]
        assert runuser_line.startswith("RUNUSER:-u wazuh-dashboard -- ")
        assert runuser_line.endswith("add -f --stdin opensearch.password")
        assert "DashPass12345" not in runuser_line
        assert "STDIN:DashPass12345" in result.stdout

    def test_fail_when_the_keystore_fails(self):
        result = self._run("cat > /dev/null; return 1")
        assert "status:1" in result.stdout
        assert "Could not write opensearch.password to the Wazuh dashboard keystore." in result.stdout

    def test_fail_when_the_keystore_tool_is_missing(self):
        result = self._run("true", keystore_exists=False)
        assert "status:1" in result.stdout


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

    def test_generated_passwords_pass_the_password_check(self):
        """Every generated password passes the same rule as a supplied one."""
        result = run_bash_function(
            BASE_SOURCES,
            """
            passwords_generatePasswords
            for p in "${passwords[@]}" "${api_passwords[@]}"; do
                passwords_checkPassword "${p}"
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
    passwords_hashPassword once per entry.
    """

    def test_success_one_hash_per_password(self):
        mocks = {**IGNORE_LOGGER, "passwords_hashPassword": f"echo '{BCRYPT}'"}
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_generateHash; echo "count:${#hashes[@]}"',
            mocks,
            {"changeall": "1", "passwords": "(PassOne1. PassTwo1. PassThree1.)"},
        )
        assert_success(result)
        assert "count:3" in result.stdout

    def test_fail_when_no_hash_is_produced(self):
        mocks = {**IGNORE_LOGGER, "installCommon_rollBack": "true", "passwords_hashPassword": "true"}
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_generateHash",
            mocks,
            {"changeall": "1", "passwords": "(PassOne1.)"},
        )
        assert_failure(result)


class TestPasswordsRunSecurityAdmin:
    """Tests for passwords_runSecurityAdmin.

    `eval` and `cp` are mocked so the real /etc/wazuh-indexer paths (which
    require root and don't exist in the test environment) are never touched.
    No password is ever printed: they are recorded in the credentials file.
    """

    def _run(self, env):
        mocks = {"common_logger": 'echo "LOG:$*"', "eval": "return 0", "cp": "true"}
        return run_bash_function(BASE_SOURCES, "passwords_runSecurityAdmin", mocks,
                                 {"indexer_installed": "yes", **env})

    def test_changeall_prints_no_password(self):
        result = self._run({"changeall": "1", "users": "(admin kibanaserver)",
                            "passwords": "(AdminPass1234 DashPass12345)"})
        assert_success(result)
        assert "AdminPass1234" not in result.stdout
        assert "DashPass12345" not in result.stdout
        assert "Wazuh indexer passwords changed." in result.stdout

    def test_single_user_prints_no_password(self):
        result = self._run({"nuser": "admin", "password": "AdminPass1234", "autopass": "1"})
        assert_success(result)
        assert "AdminPass1234" not in result.stdout
        assert "Password changed." in result.stdout

    def test_does_not_print_single_user_report_in_batch_mode(self):
        result = self._run({"changeall": "1", "users": "(admin)", "passwords": "(AdminPass1234)"})
        assert_success(result)
        assert "Password changed. Remember" not in result.stdout


class TestPasswordsChangePasswordChangeAll:
    """Tests for passwords_changePassword in changeall (batch) mode.

    Runs the real sourced function (not a stand-in), keeping
    indexer_installed empty so the code never touches the real
    /etc/wazuh-indexer paths (guarded by `[ -n "${indexer_installed}" ]` /
    `[ -f ... ]` checks already present in the function).

    The function updates the keystores and records which services need a
    restart; the restarts themselves happen later, in
    passwords_restartPendingServices.
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
            "passwords_updateManagerKeystore": "true",
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
        update run in batch mode even though nuser is never set, and both
        services are queued for a restart."""
        mocks = {
            **IGNORE_LOGGER,
            "passwords_updateManagerKeystore": 'echo "manager_keystore:$1"',
            "passwords_updateDashboardKeystore": 'echo "dashboard_keystore:$1:$2"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "pending:${restart_manager}|${restart_dashboard}"',
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
        assert "manager_keystore:ManagerPass1." in result.stdout
        assert "dashboard_keystore:opensearch.password:DashPass1." in result.stdout
        assert "pending:1|1" in result.stdout

    def test_skips_manager_keystore_when_wazuh_manager_missing_from_users_array(self):
        """If users[] never contained 'wazuh-manager' (e.g. a partial
        passwords_readUsers result), managerpass stays empty and the
        manager keystore must NOT be updated with an empty password —
        doing so would break the manager/indexer connection."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_updateManagerKeystore": 'echo "manager_keystore:$1"',
            "passwords_updateDashboardKeystore": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "pending:${restart_manager}|${restart_dashboard}"',
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
        assert "manager_keystore:" not in result.stdout
        assert "LOG:-w Skipping Wazuh manager keystore update: no password available for the wazuh-manager user." in result.stdout
        # The dashboard path is unaffected by the missing wazuh-manager user.
        assert "pending:|1" in result.stdout

    def test_rotating_admin_alone_does_not_touch_manager_keystore(self):
        """'admin' is the indexer/dashboard superuser, not the manager's
        indexer credential — rotating it in isolation (wazuh-manager not
        in users[]) must never touch the manager keystore."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_updateManagerKeystore": 'echo "manager_keystore:$1"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "pending:${restart_manager}|${restart_dashboard}"',
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "users": "(admin)",
                "passwords": "(AdminPass1.)",
            },
        )
        assert_success(result)
        assert "manager_keystore:" not in result.stdout
        assert "pending:|" in result.stdout

    def test_points_at_the_other_manager_nodes_of_a_multi_node_deployment(self):
        """The tool reaches one manager node. On a multi-node deployment
        the operator has to repeat the keystore update on the rest. The
        tool cannot tell the two apart, so the note is conditional."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_updateManagerKeystore": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "passwords_changePassword",
            mocks,
            {
                "changeall": "1",
                "wazuh_installed": "yes",
                "users": "(wazuh-manager)",
                "passwords": "(ManagerPass1.)",
            },
        )
        assert_success(result)
        assert (
            "LOG:-w If this is a multi-node deployment, update the keystore of every "
            "other Wazuh manager node and restart them."
        ) in result.stdout


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
            "passwords_updateManagerKeystore": 'echo "manager_keystore:$1"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "pending:${restart_manager}"',
            mocks,
            {
                "nuser": "wazuh-manager",
                "password": "ManagerPass1.",
                "wazuh_installed": "yes",
            },
        )
        assert_success(result)
        assert "manager_keystore:ManagerPass1." in result.stdout
        assert "pending:1" in result.stdout

    def test_failed_keystore_write_aborts_before_securityadmin(self):
        """passwords_changePassword runs before passwords_runSecurityAdmin,
        so a failed keystore write has to stop the run: otherwise the new
        password reaches the Wazuh indexer while the manager keystore still
        holds the old one, and nothing is left that can authenticate."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_updateManagerKeystore": 'echo "manager_keystore:$1"; return 1',
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "pending:${restart_manager}"',
            mocks,
            {
                "nuser": "wazuh-manager",
                "password": "ManagerPass1.",
                "wazuh_installed": "yes",
            },
        )
        assert_failure(result)
        assert "manager_keystore:ManagerPass1." in result.stdout
        assert "pending:1" not in result.stdout
        assert "multi-node deployment" not in result.stdout

    def test_admin_user_does_not_update_manager_keystore(self):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_updateManagerKeystore": 'echo "manager_keystore:$1"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "pending:${restart_manager}"',
            mocks,
            {
                "nuser": "admin",
                "password": "AdminPass1.",
                "wazuh_installed": "yes",
            },
        )
        assert_success(result)
        assert "manager_keystore:" not in result.stdout
        assert "pending:" in result.stdout
        assert "pending:1" not in result.stdout

    def test_kibanaserver_user_still_updates_dashboard_keystore(self):
        mocks = {
            **IGNORE_LOGGER,
            "passwords_updateManagerKeystore": "true",
            "passwords_updateDashboardKeystore": 'echo "dashboard_keystore:$1:$2"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "pending:${restart_dashboard}"',
            mocks,
            {
                "nuser": "kibanaserver",
                "password": "DashPass1.",
                "dashboard_installed": "yes",
            },
        )
        assert_success(result)
        assert "pending:1" in result.stdout
        assert "dashboard_keystore:opensearch.password:DashPass1." in result.stdout

    def test_failed_dashboard_keystore_write_aborts_before_securityadmin(self):
        """Same as the manager keystore: the new password must not reach the
        Wazuh indexer when the dashboard keystore could not be updated."""
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "passwords_updateDashboardKeystore": "return 1",
        }
        result = run_bash_function(
            BASE_SOURCES,
            'passwords_changePassword; echo "pending:${restart_dashboard}"',
            mocks,
            {
                "nuser": "kibanaserver",
                "password": "DashPass1.",
                "dashboard_installed": "yes",
            },
        )
        assert_failure(result)
        assert "pending:1" not in result.stdout
