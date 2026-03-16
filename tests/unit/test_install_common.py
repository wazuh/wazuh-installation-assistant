"""
Unit tests for install_functions/installCommon.sh

Covers: installCommon_getConfig, installCommon_installPrerequisites,
        installCommon_startService
"""

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

INSTALL_COMMON = "install_functions/installCommon.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, INSTALL_COMMON]

IGNORE_LOGGER = {"common_logger": "true"}


class TestInstallCommonGetConfig:
    """Tests for installCommon_getConfig.

    Requires exactly 2 arguments: config name and output path.
    Looks up content from a variable named config_file_<normalized_name>.
    """

    def _run(self, args="", extra_mocks=None):
        mocks = {**IGNORE_LOGGER, "installCommon_rollBack": "true", **(extra_mocks or {})}
        return run_bash_function(BASE_SOURCES, f"installCommon_getConfig {args}", mocks)

    def test_fail_no_args(self):
        assert_failure(self._run())

    def test_fail_one_argument(self):
        assert_failure(self._run("elasticsearch"))

    def test_success_two_arguments(self, tmp_path):
        config_out = tmp_path / "config.yml"
        result = run_bash_function(
            BASE_SOURCES,
            f'installCommon_getConfig "certificate/config_aio.yml" "{config_out}"',
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
            {"config_file_certificate_config_aio": "nodes:\n  - name: node1\n"},
        )
        assert_success(result)
        assert config_out.exists(), "output config file should have been created"

    def test_fail_unknown_config_name(self, tmp_path):
        config_out = tmp_path / "config.yml"
        result = run_bash_function(
            BASE_SOURCES,
            f'installCommon_getConfig "unknown/config.yml" "{config_out}"',
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
        )
        assert_failure(result)


class TestInstallCommonInstallPrerequisites:
    """Tests for installCommon_installPrerequisites.

    The function dispatches based on sys_type and the first argument
    (AIO, indexer, dashboard, wazuh, assistant). We mock the actual
    install list helpers to avoid real package operations.
    """

    def _run(self, sys_type, component, extra_mocks=None):
        mocks = {
            **IGNORE_LOGGER,
            "installCommon_yumInstallList": "true",
            "installCommon_aptInstallList": "true",
            "offline_checkPrerequisites": "true",
            **(extra_mocks or {}),
        }
        return run_bash_function(
            BASE_SOURCES,
            f"installCommon_installPrerequisites {component}",
            mocks,
            {"sys_type": sys_type, "debug": ""},
        )

    def test_success_yum_indexer(self):
        result = self._run("yum", "indexer")
        assert_success(result)

    def test_success_yum_dashboard(self):
        result = self._run("yum", "dashboard")
        assert_success(result)

    def test_success_apt_indexer(self):
        result = self._run("apt-get", "indexer")
        assert_success(result)

    def test_success_apt_dashboard(self):
        result = self._run("apt-get", "dashboard")
        assert_success(result)

    def test_success_yum_aio(self):
        result = self._run("yum", "AIO")
        assert_success(result)

    def test_success_apt_aio(self):
        result = self._run("apt-get", "AIO")
        assert_success(result)


class TestInstallCommonStartService:
    """Tests for installCommon_startService.

    The function checks for systemd/init and starts a named service.
    We mock systemctl so no real service management occurs.
    """

    def _run(self, service_name, systemctl_success=True, extra_mocks=None):
        systemctl_mock = "true" if systemctl_success else "return 1"
        mocks = {
            **IGNORE_LOGGER,
            "systemctl": systemctl_mock,
            "chkconfig": "true",
            "service": "true",
            "journalctl": "true",
            "installCommon_rollBack": "true",
            **(extra_mocks or {}),
        }
        return run_bash_function(
            BASE_SOURCES,
            f"installCommon_startService {service_name}",
            mocks,
            {"debug": ""},
        )

    def test_fail_no_arguments(self):
        result = run_bash_function(
            BASE_SOURCES,
            "installCommon_startService",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
        )
        assert_failure(result)

    def test_success_start_wazuh_manager(self):
        result = self._run("wazuh-manager")
        assert_success(result)

    def test_success_start_wazuh_indexer(self):
        result = self._run("wazuh-indexer")
        assert_success(result)

    def test_fail_service_start_error(self):
        result = self._run("wazuh-manager", systemctl_success=False)
        assert_failure(result)
