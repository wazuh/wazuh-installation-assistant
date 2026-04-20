"""
Unit tests for install_functions/indexer.sh

Covers: indexer_install, indexer_configure
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

INDEXER = "install_functions/indexer.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, INDEXER]

IGNORE_LOGGER = {"common_logger": "true"}


class TestIndexerInstall:
    """Tests for indexer_install.

    The function:
    1. Finds the pre-downloaded package file in download_dir.
    2. Installs via installCommon_yumInstall or installCommon_aptInstall.
    3. Calls common_checkInstalled and checks install_result / indexer_installed.
    4. Runs sysctl on success.
    """

    def _run(self, sys_type, sep, tmp_path, pkg_install_success=True):
        ext = "rpm" if sys_type == "yum" else "deb"
        pkg_dir = tmp_path / "packages"
        pkg_dir.mkdir()
        (pkg_dir / f"wazuh-indexer-5.9.9-1.x86_64.{ext}").touch()

        install_result = "0" if pkg_install_success else "1"
        indexer_installed = "1" if pkg_install_success else ""

        mocks = {
            **IGNORE_LOGGER,
            "installCommon_aptInstall": f"install_result={install_result}",
            "installCommon_yumInstall": f"install_result={install_result}",
            "common_checkInstalled": f"indexer_installed={indexer_installed}; install_result={install_result}",
            "installCommon_rollBack": "true",
            "sysctl": "true",
        }
        return run_bash_function(
            BASE_SOURCES,
            "indexer_install",
            mocks,
            {
                "sys_type": sys_type,
                "sep": sep,
                "indexer_version": "5.9.9",
                "indexer_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
                "debug": "",
            },
        )

    def test_fail_package_not_found_yum(self, tmp_path):
        """Exit 1 when no .rpm package file is present in download_dir."""
        result = run_bash_function(
            BASE_SOURCES,
            "indexer_install",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true", "sysctl": "true"},
            {
                "sys_type": "yum",
                "sep": "-",
                "indexer_version": "5.9.9",
                "indexer_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
                "debug": "",
            },
        )
        assert_failure(result)

    def test_fail_package_not_found_apt(self, tmp_path):
        """Exit 1 when no .deb package file is present in download_dir."""
        result = run_bash_function(
            BASE_SOURCES,
            "indexer_install",
            {**IGNORE_LOGGER, "installCommon_rollBack": "true", "sysctl": "true"},
            {
                "sys_type": "apt-get",
                "sep": "=",
                "indexer_version": "5.9.9",
                "indexer_revision": "1",
                "base_path": str(tmp_path),
                "download_packages_directory": "packages",
                "debug": "",
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
        """Exit 0 when yum install succeeds and indexer is detected."""
        result = self._run("yum", "-", tmp_path, pkg_install_success=True)
        assert_success(result)

    def test_success_apt_install(self, tmp_path):
        """Exit 0 when apt install succeeds and indexer is detected."""
        result = self._run("apt-get", "=", tmp_path, pkg_install_success=True)
        assert_success(result)


class TestIndexerConfigure:
    """Tests for indexer_configure.

    The function reads RAM, updates jvm.options, opensearch.yml, and copies certs.
    All file operations are mocked so no system state is required.
    """

    def _run(self, node_names, node_ips, indxname, aio=False, extra_mocks=None):
        mocks = {
            **IGNORE_LOGGER,
            "free": "echo 'Mem: 8192 4096 1024'",
            "awk": "echo 4096",
            "sed": "true",
            "indexer_copyCertificates": "true",
            "java": "true",
            "grep": "echo ''",
            **(extra_mocks or {}),
        }
        env = {
            "indexer_node_names": f"({' '.join(node_names)})",
            "indexer_node_ips": f"({' '.join(node_ips)})",
            "indxname": indxname,
            "debug": "",
        }
        if aio:
            env["AIO"] = "1"
        return run_bash_function(BASE_SOURCES, "indexer_configure", mocks, env)

    def test_success_single_node(self):
        result = self._run(["indexer1"], ["1.1.1.1"], "indexer1")
        assert_success(result)

    def test_success_aio_mode(self):
        result = self._run(["indexer1"], ["1.1.1.1"], "indexer1", aio=True)
        assert_success(result)

    def test_success_multi_node(self):
        result = self._run(
            ["indexer1", "indexer2"],
            ["1.1.1.1", "2.2.2.2"],
            "indexer1",
        )
        assert_success(result)
