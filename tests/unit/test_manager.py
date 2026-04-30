"""
Unit tests for install_functions/manager.sh

Covers: manager_install, manager_startCluster
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

MANAGER = "install_functions/manager.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, MANAGER]

IGNORE_LOGGER = {"common_logger": "true"}


class TestManagerInstall:
    """Tests for manager_install.

    The function:
    1. Finds the pre-downloaded package file in download_dir.
    2. Installs via installCommon_yumInstall or installCommon_aptInstall.
    3. Calls common_checkInstalled and checks install_result / wazuh_installed.
    """

    def _run(self, sys_type, sep, tmp_path, pkg_install_success=True):
        ext = "rpm" if sys_type == "yum" else "deb"
        pkg_dir = tmp_path / "packages"
        pkg_dir.mkdir()
        (pkg_dir / f"wazuh-manager-5.0.0.x86_64.{ext}").touch()

        install_result = "0" if pkg_install_success else "1"
        wazuh_installed = "1" if pkg_install_success else ""

        mocks = {
            **IGNORE_LOGGER,
            "installCommon_aptInstall": f"install_result={install_result}",
            "installCommon_yumInstall": f"install_result={install_result}",
            "common_checkInstalled": f"wazuh_installed={wazuh_installed}; install_result={install_result}",
            "installCommon_rollBack": "true",
        }
        return run_bash_function(
            BASE_SOURCES,
            "manager_install",
            mocks,
            {
                "sys_type": sys_type,
                "sep": sep,
                "wazuh_version": "5.0.0",
                "wazuh_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
            },
        )

    def test_fail_package_not_found_yum(self, tmp_path):
        """Exit 1 when no .rpm package file is present in download_dir."""
        result = run_bash_function(
            BASE_SOURCES,
            "manager_install",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
            {
                "sys_type": "yum",
                "sep": "-",
                "wazuh_version": "5.0.0",
                "wazuh_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
            },
        )
        assert_failure(result)

    def test_fail_package_not_found_apt(self, tmp_path):
        """Exit 1 when no .deb package file is present in download_dir."""
        result = run_bash_function(
            BASE_SOURCES,
            "manager_install",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
            {
                "sys_type": "apt-get",
                "sep": "=",
                "wazuh_version": "5.0.0",
                "wazuh_revision": "1",
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
        """Exit 0 when yum package install succeeds and component is detected."""
        result = self._run("yum", "-", tmp_path, pkg_install_success=True)
        assert_success(result)

    def test_success_apt_install(self, tmp_path):
        """Exit 0 when apt package install succeeds and component is detected."""
        result = self._run("apt-get", "=", tmp_path, pkg_install_success=True)
        assert_success(result)

    def test_fail_package_not_found_zypper(self, tmp_path):
        """Exit 1 when no .rpm package file is present for zypper."""
        result = run_bash_function(
            BASE_SOURCES,
            "manager_install",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true"},
            {
                "sys_type": "zypper",
                "sep": "-",
                "wazuh_version": "5.0.0",
                "wazuh_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
            },
        )
        assert_failure(result)

    def test_fail_zypper_install_error(self, tmp_path):
        """Exit 1 when zypper package install fails."""
        result = self._run("zypper", "-", tmp_path, pkg_install_success=False)
        assert_failure(result)

    def test_success_zypper_install(self, tmp_path):
        """Exit 0 when zypper package install succeeds and component is detected."""
        ext = "rpm"
        pkg_dir = tmp_path / "packages"
        pkg_dir.mkdir()
        (pkg_dir / f"wazuh-manager-5.0.0-1.x86_64.{ext}").touch()
        mocks = {
            **IGNORE_LOGGER,
            "installCommon_zypperInstall": "install_result=0",
            "common_checkInstalled": "wazuh_installed=1; install_result=0",
            "installCommon_rollBack": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "manager_install",
            mocks,
            {
                "sys_type": "zypper",
                "sep": "-",
                "wazuh_version": "5.0.0",
                "wazuh_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
            },
        )
        assert_success(result)


class TestManagerStartCluster:
    """Tests for manager_startCluster.

    The function iterates over node name/type arrays, reads the cluster key
    from a tar file, and patches the manager config with sed.
    """

    def _run(self, extra_mocks=None):
        mocks = {
            **IGNORE_LOGGER,
            "tar": "echo myclusterkey",
            "grep": "echo 10",
            "sed": "true",
            **(extra_mocks or {}),
        }
        return run_bash_function(
            BASE_SOURCES,
            "manager_startCluster",
            mocks,
            {
                "manager_node_names": "(wazuh-master wazuh-worker)",
                "manager_node_ips": "(1.1.1.1 2.2.2.2)",
                "manager_node_types": "(master worker)",
                "winame": "wazuh-master",
                "tar_file": "/tmp/wazuh-install-files.tar",
                "debug": "",
            },
        )

    def test_success_configures_cluster(self):
        result = self._run()
        assert_success(result)

    def test_success_with_worker_node(self):
        mocks = {
            **IGNORE_LOGGER,
            "tar": "echo myclusterkey",
            "grep": "echo 10",
            "sed": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "manager_startCluster",
            mocks,
            {
                "manager_node_names": "(wazuh-master wazuh-worker)",
                "manager_node_ips": "(1.1.1.1 2.2.2.2)",
                "manager_node_types": "(master worker)",
                "winame": "wazuh-worker",
                "tar_file": "/tmp/wazuh-install-files.tar",
                "debug": "",
            },
        )
        assert_success(result)
