"""
Unit tests for install_functions/indexer.sh

Covers: indexer_install, indexer_configure, indexer_copyCertificates,
        indexer_startCluster
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

INDEXER = "install_functions/indexer.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, INDEXER]

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
        (pkg_dir / f"wazuh-indexer-5.0.0.x86_64.{ext}").touch()

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
                "indexer_version": "5.0.0",
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
                "indexer_version": "5.0.0",
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
                "indexer_version": "5.0.0",
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

    def _sed_calls(self, tmp_path, **kwargs):
        log = tmp_path / "sed.log"
        result = self._run(extra_mocks={"sed": f'printf "%s\\n" "$*" >> "{log}"'}, **kwargs)
        assert_success(result)
        return log.read_text()

    def test_aio_keeps_the_package_configuration(self, tmp_path):
        """Only the heap and a local-only network.host; nodes_dn is the package's."""
        calls = self._sed_calls(tmp_path, node_names=["indexer1"], node_ips=["1.1.1.1"], indxname="indexer1", aio=True)
        assert 'network.host: "127.0.0.1"' in calls
        assert "nodes_dn" not in calls
        assert "node.name" not in calls

    def test_distributed_lists_every_node_in_the_certificate_format(self, tmp_path):
        calls = self._sed_calls(
            tmp_path, node_names=["indexer1", "indexer2"], node_ips=["1.1.1.1", "2.2.2.2"], indxname="indexer1"
        )
        assert "C=US,L=California,O=Wazuh,OU=Wazuh,CN=indexer1" in calls
        assert "C=US,L=California,O=Wazuh,OU=Wazuh,CN=indexer2" in calls
        assert "CN=indexer1,OU=Wazuh" not in calls


class TestIndexerCopyCertificates:
    """indexer_copyCertificates places the node and admin pairs before the install."""

    def _run(self, tmp_path, members):
        tar = make_tar(tmp_path, members)
        cert_path = tmp_path / "certs"
        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installCommon.sh"],
            "indexer_copyCertificates",
            {**IGNORE_LOGGER, "install": FAKE_INSTALL},
            {"indxname": "indexer1", "indexer_cert_path": str(cert_path), "tar_file": str(tar), "debug": ""},
        )
        return result, cert_path

    def test_success_places_pairs_with_package_names(self, tmp_path):
        result, cert_path = self._run(tmp_path, ["indexer1.pem", "indexer1-key.pem", "admin.pem", "admin-key.pem"])
        assert_success(result)
        assert (cert_path / "indexer.pem").read_text() == "indexer1.pem"
        assert (cert_path / "indexer-key.pem").read_text() == "indexer1-key.pem"
        assert (cert_path / "admin.pem").read_text() == "admin.pem"
        assert (cert_path / "admin-key.pem").read_text() == "admin-key.pem"

    def test_fail_when_admin_pair_missing(self, tmp_path):
        result, _ = self._run(tmp_path, ["indexer1.pem", "indexer1-key.pem"])
        assert_failure(result)


class TestIndexerStartCluster:
    """indexer_startCluster runs the security initializer the package ships."""

    def _run(self, rc):
        return run_bash_function(
            BASE_SOURCES,
            "indexer_startCluster",
            {**IGNORE_LOGGER, "bash": f'[[ "$*" == *indexer-security-init.sh* ]] && return {rc}', "installCommon_rollBack": "true"},
            {"debug": ""},
        )

    def test_success(self):
        assert_success(self._run(0))

    def test_fail_when_the_initializer_fails(self):
        assert_failure(self._run(1))
