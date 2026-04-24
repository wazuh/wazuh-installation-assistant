"""
Unit tests for install_functions/dashboard.sh

Covers: dashboard_install, dashboard_configure
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

DASHBOARD = "install_functions/dashboard.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, DASHBOARD]

IGNORE_LOGGER = {"common_logger": "true"}


class TestDashboardInstall:
    """Tests for dashboard_install.

    The function:
    1. Finds the pre-downloaded package file in download_dir.
    2. Installs via installCommon_yumInstall or installCommon_aptInstall.
    3. Calls common_checkInstalled and checks install_result / dashboard_installed.
    """

    def _run(self, sys_type, sep, tmp_path, pkg_install_success=True):
        ext = "rpm" if sys_type == "yum" else "deb"
        pkg_dir = tmp_path / "packages"
        pkg_dir.mkdir()
        (pkg_dir / f"wazuh-dashboard-1.2.3.x86_64.{ext}").touch()

        install_result = "0" if pkg_install_success else "1"
        dashboard_installed = "1" if pkg_install_success else ""

        mocks = {
            **IGNORE_LOGGER,
            "installCommon_aptInstall": f"install_result={install_result}",
            "installCommon_yumInstall": f"install_result={install_result}",
            "common_checkInstalled": f"dashboard_installed={dashboard_installed}; install_result={install_result}",
            "installCommon_rollBack": "true",
        }
        return run_bash_function(
            BASE_SOURCES,
            "dashboard_install",
            mocks,
            {
                "sys_type": sys_type,
                "sep": sep,
                "dashboard_version": "1.2.3",
                "dashboard_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
            },
        )

    def test_fail_package_not_found_yum(self, tmp_path):
        """Exit 1 when no .rpm package file is present in download_dir."""
        result = run_bash_function(
            BASE_SOURCES,
            "dashboard_install",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
            {
                "sys_type": "yum",
                "sep": "-",
                "dashboard_version": "1.2.3",
                "dashboard_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
            },
        )
        assert_failure(result)

    def test_fail_package_not_found_apt(self, tmp_path):
        """Exit 1 when no .deb package file is present in download_dir."""
        result = run_bash_function(
            BASE_SOURCES,
            "dashboard_install",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
            {
                "sys_type": "apt-get",
                "sep": "=",
                "dashboard_version": "1.2.3",
                "dashboard_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
            },
        )
        assert_failure(result)

    def test_fail_yum_install_error(self, tmp_path):
        """Exit 1 when yum package install fails."""
        result = self._run("yum", "-", tmp_path, pkg_install_success=False)
        assert_failure(result)

    def test_fail_apt_install_error(self, tmp_path):
        """Exit 1 when apt package install fails."""
        result = self._run("apt-get", "=", tmp_path, pkg_install_success=False)
        assert_failure(result)

    def test_success_yum_install(self, tmp_path):
        """Exit 0 when yum install succeeds and dashboard is detected."""
        result = self._run("yum", "-", tmp_path, pkg_install_success=True)
        assert_success(result)

    def test_success_apt_install(self, tmp_path):
        """Exit 0 when apt install succeeds and dashboard is detected."""
        result = self._run("apt-get", "=", tmp_path, pkg_install_success=True)
        assert_success(result)


class TestDashboardConfigure:
    """Tests for dashboard_configure.

    The function obtains the node IP, copies certs, and patches config files with sed.
    Array variables (node_names, node_ips) are passed as proper bash arrays.
    """

    def _run(self, extra_env=None, extra_mocks=None):
        mocks = {
            **IGNORE_LOGGER,
            "dashboard_copyCertificates": "true",
            "installCommon_getConfig": "true",
            "sed": "true",
            **(extra_mocks or {}),
        }
        env = {
            "dashboard_node_names": "(node1)",
            "dashboard_node_ips": "(1.1.1.1)",
            "indexer_node_names": "(indexer1)",
            "indexer_node_ips": "(1.1.1.1)",
            "manager_node_names": "(manager1)",
            "manager_node_ips": "(1.1.1.1)",
            "manager_node_types": "(master)",
            "dashname": "node1",
            "debug": "",
            **(extra_env or {}),
        }
        return run_bash_function(BASE_SOURCES, "dashboard_configure", mocks, env)

    def test_success_single_node(self):
        result = self._run()
        assert_success(result)

    def test_success_aio_mode(self):
        result = self._run(extra_env={"AIO": "1"})
        assert_success(result)

    def test_success_single_manager_no_node_type(self):
        """When there is a single manager without node_type, wazuh_api_address should default to manager_node_ips[0]."""
        result = self._run(
            extra_env={
                "manager_node_types": "",
            }
        )
        assert_success(result)

    def test_success_multi_indexer_nodes(self):
        result = self._run(
            extra_env={
                "indexer_node_names": "(indexer1 indexer2)",
                "indexer_node_ips": "(1.1.1.1 2.2.2.2)",
            }
        )
        assert_success(result)
