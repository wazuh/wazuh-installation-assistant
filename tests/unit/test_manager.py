"""
Unit tests for install_functions/manager.sh

Covers: manager_install, manager_startCluster, manager_configure, manager_copyCertificates,
        manager_setRemotedSans, manager_setApidSans, manager_setApiLoopback
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


class TestManagerConfigure:
    """Tests for manager_configure.

    The pairs are placed before the package creates the wazuh-manager group, so
    manager_configure gives them to the group and runs the package resolver again.
    """

    def _run(self, tmp_path, extra_mocks=None):
        return run_bash_function(
            BASE_SOURCES,
            "manager_configure",
            {**IGNORE_LOGGER, "sed": "true", **(extra_mocks or {})},
            {"manager_cert_path": "/certs", "manager_conf_file": "/conf", "indexer_node_ips": "(1.1.1.1)", "debug": ""},
        )

    def test_success_gives_every_pair_to_the_service_group(self, tmp_path):
        log = tmp_path / "perm.log"
        result = self._run(
            tmp_path,
            {"chown": f'echo "chown $*" >> "{log}"', "chmod": f'echo "chmod $*" >> "{log}"'},
        )
        assert_success(result)
        calls = log.read_text().splitlines()
        assert "chown root:wazuh-manager /certs /certs/*.pem" in calls
        assert "chmod 750 /certs" in calls
        assert "chmod 640 /certs/*.pem" in calls

    def test_success_runs_the_resolver_without_issuing(self, tmp_path):
        log = tmp_path / "resolver.log"
        result = run_bash_function(
            BASE_SOURCES,
            "manager_configure",
            {**IGNORE_LOGGER, "sed": "true", "chown": "true", "chmod": "true"},
            {
                "manager_cert_path": "/certs", "manager_conf_file": "/conf", "indexer_node_ips": "(1.1.1.1)",
                "debug": "", "manager_resolver": f'echo "resolver" >> "{log}"; echo',
            },
        )
        assert_success(result)
        assert log.read_text().splitlines() == ["resolver"]
        assert "--upgrade -H /var/wazuh-manager" in result.stdout


class TestManagerCopyCertificates:
    """Tests for manager_copyCertificates.

    Before the package is installed, the CA certificate (as the manager CA, the agents
    bundle and the indexer CA) and the pairs of the node are placed from the tar file
    with the names the package expects. The CA key is never placed.
    """

    MEMBERS = [
        "root-ca.pem", "wazuh-master.pem", "wazuh-master-key.pem", "wazuh-master-remoted.pem",
        "wazuh-master-remoted-key.pem", "wazuh-master-apid.pem", "wazuh-master-apid-key.pem",
    ]

    def _run(self, tmp_path, members):
        import subprocess

        staging = tmp_path / "wazuh-install-files"
        staging.mkdir()
        for name in members:
            (staging / name).write_text(name)
        tar_file = tmp_path / "wazuh-install-files.tar"
        subprocess.run(["tar", "-cf", str(tar_file), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
        config = tmp_path / "etc-wazuh-manager"

        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installCommon.sh"],
            "manager_copyCertificates",
            # install -o root needs root; the owner is set after the package is installed.
            {**IGNORE_LOGGER, "install": 'if [ "$1" = -d ]; then shift 7; mkdir -p "$@"; else cp "${@: -2:1}" "${@: -1}"; fi'},
            {
                "winame": "wazuh-master", "manager_config_path": str(config),
                "manager_cert_path": str(config / "certs"), "tar_file": str(tar_file), "debug": "",
            },
        )
        return result, config

    def test_success_places_pairs_with_package_names(self, tmp_path):
        result, config = self._run(tmp_path, self.MEMBERS)
        assert_success(result)
        certs = config / "certs"
        assert (config / "ca" / "root-ca.pem").read_text() == "root-ca.pem"
        assert not (config / "ca" / "root-ca.key").exists()
        assert (certs / "root-ca.pem").read_text() == "root-ca.pem"
        assert (certs / "indexer-ca.pem").read_text() == "root-ca.pem"
        assert (certs / "indexer-connector.pem").read_text() == "wazuh-master.pem"
        assert (certs / "indexer-connector-key.pem").read_text() == "wazuh-master-key.pem"
        assert (certs / "remoted.pem").read_text() == "wazuh-master-remoted.pem"
        assert (certs / "remoted-key.pem").read_text() == "wazuh-master-remoted-key.pem"
        assert (certs / "apid.pem").read_text() == "wazuh-master-apid.pem"
        assert (certs / "apid-key.pem").read_text() == "wazuh-master-apid-key.pem"

    def test_fail_when_remoted_pair_missing(self, tmp_path):
        result, _ = self._run(tmp_path, ["root-ca.pem", "wazuh-master.pem", "wazuh-master-key.pem"])
        assert_failure(result)

    def test_fail_when_apid_pair_missing(self, tmp_path):
        """A tar from a certs tool that predates the Server API pair."""
        result, _ = self._run(tmp_path, self.MEMBERS[:5])
        assert_failure(result)


class TestManagerSetRemotedSans:
    """Tests for manager_setRemotedSans.

    On an all-in-one install the manager package issues remoted.pem. Addresses given
    with -as|--agent-san reach it through WAZUH_MANAGER_REMOTED_CERT_SANS in the manager
    local.env, together with the host addresses, because the variable replaces the
    discovered list.
    """

    def _run(self, tmp_path, agent_san, function="manager_setRemotedSans", san_var="agent_san"):
        config = tmp_path / "etc-wazuh-manager"
        result = run_bash_function(
            [*BASE_SOURCES, "cert_tool/certFunctions.sh", "common_functions/credentials.sh"],
            function,
            {
                **IGNORE_LOGGER, "chown": "true",
                "install": 'mkdir -p "${@: -1}"',
                "cert_hostAddresses": "printf '%s\\n' 10.0.0.5 host.example.com",
            },
            {san_var: f"({' '.join(agent_san)})", "manager_config_path": str(config), "debug": ""},
        )
        env = config / "local.env"
        return result, env.read_text() if env.exists() else ""

    def test_success_nothing_written_without_agent_san(self, tmp_path):
        result, env = self._run(tmp_path, [])
        assert_success(result)
        assert env == ""

    def test_success_types_and_dedups_addresses(self, tmp_path):
        result, env = self._run(tmp_path, ["203.0.113.7", "wazuh.example.com", "10.0.0.5"])
        assert_success(result)
        assert env == "WAZUH_MANAGER_REMOTED_CERT_SANS=IP:203.0.113.7,DNS:wazuh.example.com,IP:10.0.0.5,DNS:host.example.com\n"


class TestManagerSetApidSans:
    """Tests for manager_setApidSans: same as the agent listener, for apid.pem."""

    def _run(self, tmp_path, api_san):
        return TestManagerSetRemotedSans()._run(tmp_path, api_san, "manager_setApidSans", "api_san")

    def test_success_nothing_written_without_api_san(self, tmp_path):
        result, env = self._run(tmp_path, [])
        assert_success(result)
        assert env == ""

    def test_success_types_and_dedups_addresses(self, tmp_path):
        result, env = self._run(tmp_path, ["203.0.113.7", "api.example.com", "10.0.0.5"])
        assert_success(result)
        assert env == "WAZUH_MANAGER_APID_CERT_SANS=IP:203.0.113.7,DNS:api.example.com,IP:10.0.0.5,DNS:host.example.com\n"
        assert "REMOTED" not in env


class TestManagerSetApiLoopback:
    """Tests for manager_setApiLoopback: on an all-in-one the Server API listens on loopback only."""

    PACKAGE_API_YAML = (
        "# USE THIS FILE AS A TEMPLATE. UNCOMMENT LINES TO APPLY CUSTOM CONFIGURATION\n"
        "\n"
        "# host: ['0.0.0.0', '::']\n"
        "# port: 55000\n"
        "\n"
        "# https:\n"
        "#  enabled: yes\n"
    )

    def _run(self, api_conf):
        return run_bash_function(
            BASE_SOURCES,
            "manager_setApiLoopback",
            {"common_logger": 'echo "LOG $*"'},
            {"manager_api_conf_file": str(api_conf), "debug": ""},
        )

    def test_success_sets_loopback_in_package_template(self, tmp_path):
        api_conf = tmp_path / "api.yaml"
        api_conf.write_text(self.PACKAGE_API_YAML)
        result = self._run(api_conf)
        assert_success(result)
        assert api_conf.read_text() == self.PACKAGE_API_YAML.replace(
            "# host: ['0.0.0.0', '::']", "host: ['127.0.0.1', '::1']"
        )
        assert "LOG -w" not in result.stdout

    def test_success_replaces_an_uncommented_host(self, tmp_path):
        api_conf = tmp_path / "api.yaml"
        api_conf.write_text("host: ['0.0.0.0', '::']\nport: 55000\n")
        result = self._run(api_conf)
        assert_success(result)
        assert api_conf.read_text() == "host: ['127.0.0.1', '::1']\nport: 55000\n"

    def test_success_warns_when_host_option_is_missing(self, tmp_path):
        api_conf = tmp_path / "api.yaml"
        api_conf.write_text("# port: 55000\n")
        result = self._run(api_conf)
        assert_success(result)
        assert api_conf.read_text() == "# port: 55000\n"
        assert "LOG -w Could not set the host option" in result.stdout

    def test_success_warns_when_file_is_missing(self, tmp_path):
        result = self._run(tmp_path / "missing.yaml")
        assert_success(result)
        assert "LOG -w Could not set the host option" in result.stdout
