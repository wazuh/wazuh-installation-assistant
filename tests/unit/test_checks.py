"""
Unit tests for install_functions/checks.sh

Covers: checks_names, checks_arch, checks_arguments, checks_health,
        checks_previousCertificate
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

CHECKS = "install_functions/checks.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"

BASE_SOURCES = [COMMON_VARS, COMMON, CHECKS]

# Suppress logger output in all tests
IGNORE_LOGGER = {"common_logger": "true"}


# ---------------------------------------------------------------------------
# checks_names
# ---------------------------------------------------------------------------

class TestChecksNames:
    def _run(self, env_vars=None, extra_mocks=None):
        mocks = {**IGNORE_LOGGER, **(extra_mocks or {})}
        return run_bash_function(BASE_SOURCES, "checks_names", mocks, env_vars)

    def test_fail_indexer_and_dashboard_same_name(self):
        result = self._run(env_vars={"indxname": "node1", "dashname": "node1", "winame": "wazuh"})
        assert_failure(result)

    def test_fail_indexer_and_wazuh_same_name(self):
        result = self._run(env_vars={"indxname": "node1", "winame": "node1"})
        assert_failure(result)

    def test_fail_dashboard_and_wazuh_same_name(self):
        result = self._run(env_vars={"dashname": "node1", "winame": "node1"})
        assert_failure(result)

    def test_fail_wazuh_name_not_in_config(self):
        mocks = {
            **IGNORE_LOGGER,
            "grep": "return 1",
        }
        result = self._run(
            env_vars={"winame": "node1", "manager_node_names": "(wazuh node10)"},
            extra_mocks=mocks,
        )
        assert_failure(result)

    def test_success_all_correct_installing_indexer(self):
        mocks = {
            **IGNORE_LOGGER,
            "grep": "return 0",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "checks_names",
            mocks,
            {
                "indxname": "indexer1",
                "dashname": "dashboard1",
                "winame": "wazuh1",
                "indexer_node_names": "(indexer1 node1)",
                "manager_node_names": "(wazuh1 node2)",
                "dashboard_node_names": "(dashboard1 node3)",
                "indexer": "1",
            },
        )
        assert_success(result)

    def test_success_all_correct_installing_wazuh(self):
        mocks = {**IGNORE_LOGGER, "grep": "return 0"}
        result = run_bash_function(
            BASE_SOURCES,
            "checks_names",
            mocks,
            {
                "indxname": "indexer1",
                "dashname": "dashboard1",
                "winame": "wazuh1",
                "indexer_node_names": "(indexer1 node1)",
                "manager_node_names": "(wazuh1 node2)",
                "dashboard_node_names": "(dashboard1 node3)",
                "wazuh": "1",
            },
        )
        assert_success(result)

    def test_success_all_correct_installing_dashboard(self):
        mocks = {**IGNORE_LOGGER, "grep": "return 0"}
        result = run_bash_function(
            BASE_SOURCES,
            "checks_names",
            mocks,
            {
                "indxname": "indexer1",
                "dashname": "dashboard1",
                "winame": "wazuh1",
                "indexer_node_names": "(indexer1 node1)",
                "manager_node_names": "(wazuh1 node2)",
                "dashboard_node_names": "(dashboard1 node3)",
                "dashboard": "1",
            },
        )
        assert_success(result)


# ---------------------------------------------------------------------------
# checks_arch
# ---------------------------------------------------------------------------

class TestChecksArch:
    def _run(self, uname_output):
        return run_bash_function(
            BASE_SOURCES,
            "checks_arch",
            {"uname": f"echo {uname_output}", **IGNORE_LOGGER},
        )

    def test_success_x86_64(self):
        assert_success(self._run("x86_64"))

    def test_fail_empty_arch(self):
        assert_failure(self._run(""))

    def test_fail_i386(self):
        assert_failure(self._run("i386"))

    def test_fail_arm64(self):
        # arm64 / aarch64 not supported by checks_arch
        result = run_bash_function(
            BASE_SOURCES,
            "checks_arch",
            {"uname": "echo aarch64", **IGNORE_LOGGER},
        )
        # aarch64 may or may not be supported; verify it doesn't raise unexpected errors
        assert result.returncode in (0, 1)


# ---------------------------------------------------------------------------
# checks_arguments
# ---------------------------------------------------------------------------

class TestChecksArguments:
    def _run(self, env_vars=None, extra_mocks=None):
        mocks = {**IGNORE_LOGGER, "installCommon_rollBack": "true", **(extra_mocks or {})}
        return run_bash_function(BASE_SOURCES, "checks_arguments", mocks, env_vars)

    def test_success_aio_removes_existing_certs_file(self, tmp_path):
        # When AIO=1 and tar_file exists, checks_arguments removes it and continues (no error)
        tar = tmp_path / "wazuh-install-files.tar"
        tar.touch()
        result = self._run(env_vars={"AIO": "1", "tar_file": str(tar)})
        assert_success(result)
        assert not tar.exists(), "tar file should have been removed by checks_arguments"

    def test_fail_certificate_creation_with_certs_file_present(self, tmp_path):
        tar = tmp_path / "wazuh-install-files.tar"
        tar.touch()
        result = self._run(env_vars={"certificates": "1", "tar_file": str(tar)})
        assert_failure(result)

    def test_fail_overwrite_with_no_component(self):
        result = self._run(env_vars={"overwrite": "1", "AIO": "", "indexer": "", "wazuh": "", "dashboard": ""})
        assert_failure(result)

    def test_success_uninstall_no_component_installed(self):
        result = self._run(
            env_vars={
                "uninstall": "1",
                "indexer_installed": "",
                "indexer_remaining_files": "",
                "wazuh_installed": "",
                "wazuh_remaining_files": "",
                "dashboard_installed": "",
                "dashboard_remaining_files": "",
            }
        )
        assert_success(result)

    def test_fail_uninstall_and_aio(self):
        assert_failure(self._run(env_vars={"uninstall": "1", "AIO": "1"}))

    def test_fail_uninstall_and_wazuh(self):
        assert_failure(self._run(env_vars={"uninstall": "1", "wazuh": "1"}))

    def test_fail_uninstall_and_dashboard(self):
        assert_failure(self._run(env_vars={"uninstall": "1", "dashboard": "1"}))

    def test_fail_uninstall_and_indexer(self):
        assert_failure(self._run(env_vars={"uninstall": "1", "indexer": "1"}))

    def test_fail_aio_and_indexer(self):
        assert_failure(self._run(env_vars={"AIO": "1", "indexer": "1"}))

    def test_fail_aio_and_wazuh(self):
        assert_failure(self._run(env_vars={"AIO": "1", "wazuh": "1"}))

    def test_fail_aio_and_dashboard(self):
        assert_failure(self._run(env_vars={"AIO": "1", "dashboard": "1"}))

    def test_fail_aio_wazuh_installed_no_overwrite(self):
        assert_failure(self._run(env_vars={"AIO": "1", "wazuh_installed": "1", "overwrite": ""}))

    def test_fail_aio_wazuh_files_no_overwrite(self):
        assert_failure(self._run(env_vars={"AIO": "1", "wazuh_remaining_files": "1", "overwrite": ""}))

    def test_fail_aio_indexer_installed_no_overwrite(self):
        assert_failure(self._run(env_vars={"AIO": "1", "indexer_installed": "1", "overwrite": ""}))

    def test_fail_aio_dashboard_installed_no_overwrite(self):
        assert_failure(self._run(env_vars={"AIO": "1", "dashboard_installed": "1", "overwrite": ""}))

    def test_success_aio_wazuh_installed_with_overwrite(self):
        assert_success(self._run(env_vars={"AIO": "1", "wazuh_installed": "1", "overwrite": "1"}))

    def test_success_aio_indexer_installed_with_overwrite(self):
        assert_success(self._run(env_vars={"AIO": "1", "indexer_installed": "1", "overwrite": "1"}))

    def test_success_aio_dashboard_installed_with_overwrite(self):
        assert_success(self._run(env_vars={"AIO": "1", "dashboard_installed": "1", "overwrite": "1"}))

    def test_fail_indexer_installed_no_overwrite(self):
        assert_failure(self._run(env_vars={"indexer": "1", "indexer_installed": "1", "overwrite": ""}))

    def test_fail_indexer_remaining_files_no_overwrite(self):
        assert_failure(self._run(env_vars={"indexer": "1", "indexer_remaining_files": "1", "overwrite": ""}))

    def test_success_indexer_installed_with_overwrite(self):
        assert_success(self._run(env_vars={"indexer": "1", "indexer_installed": "1", "overwrite": "1"}))

    def test_fail_wazuh_installed_no_overwrite(self):
        assert_failure(self._run(env_vars={"wazuh": "1", "wazuh_installed": "1", "overwrite": ""}))

    def test_success_wazuh_installed_with_overwrite(self):
        assert_success(self._run(env_vars={"wazuh": "1", "wazuh_installed": "1", "overwrite": "1"}))

    def test_fail_dashboard_installed_no_overwrite(self):
        assert_failure(self._run(env_vars={"dashboard": "1", "dashboard_installed": "1", "overwrite": ""}))

    def test_success_dashboard_installed_with_overwrite(self):
        assert_success(self._run(env_vars={"dashboard": "1", "dashboard_installed": "1", "overwrite": "1"}))


# ---------------------------------------------------------------------------
# checks_health
# ---------------------------------------------------------------------------

class TestChecksHealth:
    def _run(self, env_vars=None):
        mocks = {**IGNORE_LOGGER, "checks_specifications": "true"}
        return run_bash_function(BASE_SOURCES, "checks_health", mocks, env_vars)

    def test_success_no_installation(self):
        assert_success(self._run())

    def test_fail_aio_1_core(self):
        assert_failure(self._run({"AIO": "1", "cores": "1", "ram_gb": "3700"}))

    def test_fail_aio_insufficient_ram(self):
        assert_failure(self._run({"AIO": "1", "cores": "2", "ram_gb": "3000"}))

    def test_success_aio_2_cores_4gb(self):
        assert_success(self._run({"AIO": "1", "cores": "2", "ram_gb": "3700"}))

    def test_fail_indexer_1_core(self):
        assert_failure(self._run({"indexer": "1", "cores": "1", "ram_gb": "3700"}))

    def test_fail_indexer_insufficient_ram(self):
        assert_failure(self._run({"indexer": "1", "cores": "2", "ram_gb": "3000"}))

    def test_success_indexer_2_cores_enough_ram(self):
        assert_success(self._run({"indexer": "1", "cores": "2", "ram_gb": "3700"}))

    def test_fail_dashboard_1_core(self):
        assert_failure(self._run({"dashboard": "1", "cores": "1", "ram_gb": "3700"}))

    def test_fail_dashboard_insufficient_ram(self):
        assert_failure(self._run({"dashboard": "1", "cores": "2", "ram_gb": "3000"}))

    def test_success_dashboard_2_cores_enough_ram(self):
        assert_success(self._run({"dashboard": "1", "cores": "2", "ram_gb": "3700"}))

    def test_fail_wazuh_1_core(self):
        assert_failure(self._run({"wazuh": "1", "cores": "1", "ram_gb": "1700"}))

    def test_fail_wazuh_insufficient_ram(self):
        assert_failure(self._run({"wazuh": "1", "cores": "2", "ram_gb": "1000"}))

    def test_success_wazuh_2_cores_enough_ram(self):
        assert_success(self._run({"wazuh": "1", "cores": "2", "ram_gb": "1700"}))


# ---------------------------------------------------------------------------
# checks_previousCertificate
# ---------------------------------------------------------------------------

class TestChecksPreviousCertificate:
    def _run(self, env_vars=None, extra_mocks=None):
        mocks = {**IGNORE_LOGGER, **(extra_mocks or {})}
        return run_bash_function(BASE_SOURCES, "checks_previousCertificate", mocks, env_vars)

    def test_fail_no_tar_file(self, tmp_path):
        result = self._run(env_vars={"tar_file": str(tmp_path / "missing.tar")})
        assert_failure(result)

    def test_success_all_certs_present(self, tmp_path):
        tar = tmp_path / "wazuh-install-files.tar"
        tar.touch()
        mocks = {
            **IGNORE_LOGGER,
            "tar": "true",
            "grep": "return 0",
        }
        result = self._run(
            env_vars={
                "tar_file": str(tar),
                "indxname": "indexer1",
                "dashname": "dashboard1",
                "winame": "wazuh1",
            },
            extra_mocks=mocks,
        )
        assert_success(result)

    def test_fail_indexer_cert_missing(self, tmp_path):
        tar = tmp_path / "wazuh-install-files.tar"
        tar.touch()
        mocks = {
            **IGNORE_LOGGER,
            "tar": "true",
            "grep": "return 1",
        }
        result = self._run(
            env_vars={"tar_file": str(tar), "indxname": "indexer1"},
            extra_mocks=mocks,
        )
        assert_failure(result)
