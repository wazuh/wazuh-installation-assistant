"""
Unit tests for install_functions/dashboard.sh

Covers: dashboard_install, dashboard_configure, dashboard_copyCertificates,
        dashboard_displaySummary
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

DASHBOARD = "install_functions/dashboard.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, DASHBOARD]

IGNORE_LOGGER = {"common_logger": "true"}


def make_tar(tmp_path, members):
    """Build a wazuh-install-files.tar holding files named after themselves."""
    import subprocess

    staging = tmp_path / "wazuh-install-files"
    staging.mkdir()
    for name in members:
        (staging / name).write_text(name)
    tar = tmp_path / "wazuh-install-files.tar"
    subprocess.run(["tar", "-cf", str(tar), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
    return tar


# install -o root needs root; the owner of a pre-placed pair is the package's job anyway.
FAKE_INSTALL = 'if [ "$1" = -d ]; then mkdir -p "${@: -1}"; else cp "${@: -2:1}" "${@: -1}"; fi'


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
        (pkg_dir / f"wazuh-dashboard-5.0.0.x86_64.{ext}").touch()

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
                "dashboard_version": "5.0.0",
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
                "dashboard_version": "5.0.0",
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
                "dashboard_version": "5.0.0",
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
            "chown": "true",
            "chmod": "true",
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

    def test_success_gives_the_certificates_to_the_service_user(self, tmp_path):
        """The package keeps a pre-placed pair as it is, owned by root."""
        log = tmp_path / "perm.log"
        result = self._run(
            extra_env={"dashboard_cert_path": "/certs"},
            extra_mocks={"chown": f'echo "chown $*" >> "{log}"', "chmod": f'echo "chmod $*" >> "{log}"'},
        )
        assert_success(result)
        calls = log.read_text().splitlines()
        assert "chown -R wazuh-dashboard:wazuh-dashboard /certs" in calls
        assert "chmod 500 /certs" in calls


class TestDashboardCopyCertificates:
    """dashboard_copyCertificates places the node pair before the install."""

    def test_success_places_pair_with_package_names(self, tmp_path):
        tar = make_tar(tmp_path, ["dashboard1.pem", "dashboard1-key.pem"])
        cert_path = tmp_path / "certs"
        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installCommon.sh"],
            "dashboard_copyCertificates",
            {**IGNORE_LOGGER, "install": FAKE_INSTALL},
            {"dashname": "dashboard1", "dashboard_cert_path": str(cert_path), "tar_file": str(tar), "debug": ""},
        )
        assert_success(result)
        assert (cert_path / "dashboard.pem").read_text() == "dashboard1.pem"
        assert (cert_path / "dashboard-key.pem").read_text() == "dashboard1-key.pem"


class TestDashboardDisplaySummary:
    def test_points_to_the_credentials_file_without_printing_a_password(self):
        result = run_bash_function(BASE_SOURCES, "dashboard_displaySummary", {"common_logger": 'echo "$*"'}, {"http_port": "443", "AIO": "1"})
        assert_success(result)
        assert "Password: admin" not in result.stdout
        assert "WAZUH_INDEXER_ADMIN_PASSWORD value in /etc/wazuh/credentials.env" in result.stdout

    def test_distributed_node_points_to_the_tar_file(self):
        """A dashboard node does not receive the admin password, so it is read elsewhere."""
        result = run_bash_function(
            BASE_SOURCES,
            "dashboard_displaySummary",
            {"common_logger": 'echo "$*"'},
            {"http_port": "443", "tar_file_name": "wazuh-install-files.tar"},
        )
        assert_success(result)
        assert "credentials.env file of wazuh-install-files.tar" in result.stdout
        assert "of a Wazuh indexer node" in result.stdout
