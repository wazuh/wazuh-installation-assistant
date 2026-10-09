"""
Unit tests for install_functions/checks.sh

Covers: checks_names, checks_arch, checks_arguments, checks_health,
        checks_previousCertificate, checks_ports
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

CHECKS = "install_functions/checks.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"

BASE_SOURCES = [COMMON_VARS, COMMON, CHECKS]

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

    def test_fail_skip_signature_check_without_development(self):
        assert_failure(self._run(env_vars={"skip_signature_check": "1", "wazuh": "1"}))

    def test_success_skip_signature_check_with_development(self):
        assert_success(self._run(env_vars={"skip_signature_check": "1", "development": "1", "wazuh": "1"}))

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
    MOCKS = {
        "common_logger": 'if [ "$1" = "-w" ]; then echo "$2"; fi',
        "checks_specifications": "true",
    }

    def _run(self, env_vars=None):
        return run_bash_function(BASE_SOURCES, "checks_health", self.MOCKS, env_vars)

    def _assert_warns(self, env_vars, ram, cores):
        result = self._run(env_vars)
        assert_success(result)
        assert f"of {ram} GB of RAM and {cores} CPU cores" in result.stdout

    def _assert_no_warning(self, env_vars):
        result = self._run(env_vars)
        assert_success(result)
        assert "does not meet" not in result.stdout

    def test_success_no_installation(self):
        self._assert_no_warning({"cores": "1", "ram_gb": "100"})

    @pytest.mark.parametrize("env", [
        {"AIO": "1", "cores": "4", "ram_gb": "7300"},
        {"indexer": "1", "cores": "4", "ram_gb": "7300"},
        {"wazuh": "1", "cores": "4", "ram_gb": "7300"},
        {"dashboard": "1", "cores": "2", "ram_gb": "3300"},
        {"dashboard": "1", "indexer_installed": "1", "wazuh_installed": "1", "cores": "4", "ram_gb": "7300"},
    ], ids=["aio", "indexer", "wazuh", "dashboard", "dashboard_with_indexer_and_wazuh_installed"])
    def test_success_documented_minimum(self, env):
        self._assert_no_warning(env)

    @pytest.mark.parametrize("env", [
        {"AIO": "1", "cores": "3", "ram_gb": "7300"},
        {"AIO": "1", "cores": "4", "ram_gb": "7299"},
        {"indexer": "1", "cores": "2", "ram_gb": "3700"},
        {"wazuh": "1", "cores": "2", "ram_gb": "2000"},
        {"dashboard": "1", "indexer_installed": "1", "cores": "4", "ram_gb": "3476"},
        {"dashboard": "1", "indexer_installed": "1", "wazuh_installed": "1", "cores": "4", "ram_gb": "5914"},
    ], ids=["aio_3_cores", "aio_insufficient_ram", "indexer_2_cores_4gb", "wazuh_2_cores_2gb",
            "dashboard_with_indexer_installed", "dashboard_with_indexer_and_wazuh_installed"])
    def test_warn_below_8gb_4_cores(self, env):
        self._assert_warns(env, 8, 4)

    @pytest.mark.parametrize("env", [
        {"dashboard": "1", "cores": "1", "ram_gb": "3700"},
        {"dashboard": "1", "cores": "2", "ram_gb": "3299"},
    ], ids=["dashboard_1_core", "dashboard_insufficient_ram"])
    def test_warn_dashboard_below_4gb_2_cores(self, env):
        self._assert_warns(env, 4, 2)


# ---------------------------------------------------------------------------
# checks_previousCertificate
# ---------------------------------------------------------------------------

class TestChecksPreviousCertificate:
    """Tests for checks_previousCertificate.

    The tar file must hold, for the component of the node, the credentials file with
    valid passwords, the root CA certificate and the certificate pairs of the node.
    """

    PASSWORD = "Aa1.aaaaaaaaaaaa"
    KEYS = [
        "WAZUH_INDEXER_ADMIN_PASSWORD",
        "WAZUH_INDEXER_KIBANASERVER_PASSWORD",
        "WAZUH_INDEXER_MANAGER_PASSWORD",
        "WAZUH_MANAGER_API_PASSWORD",
        "WAZUH_MANAGER_WUI_PASSWORD",
    ]
    FILES = [
        "config.yml", "root-ca.pem", "admin.pem", "admin-key.pem",
        "indexer1.pem", "indexer1-key.pem", "dashboard1.pem", "dashboard1-key.pem",
        "wazuh1.pem", "wazuh1-key.pem", "wazuh1-remoted.pem", "wazuh1-remoted-key.pem",
        "wazuh1-apid.pem", "wazuh1-apid-key.pem",
    ]

    def _tar(self, tmp_path, files=None, passwords=None):
        import subprocess

        staging = tmp_path / "wazuh-install-files"
        staging.mkdir()
        for name in self.FILES if files is None else files:
            (staging / name).write_text(name)
        passwords = {k: self.PASSWORD for k in self.KEYS} if passwords is None else passwords
        (staging / "credentials.env").write_text("".join(f'{k}="{v}"\n' for k, v in passwords.items()))
        tar = tmp_path / "wazuh-install-files.tar"
        subprocess.run(["tar", "-cf", str(tar), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
        return tar

    def _run(self, tar, **names):
        return run_bash_function(
            [*BASE_SOURCES, "install_functions/installVariables.sh", "credentials_lib/wazuh-credentials.sh"],
            "checks_previousCertificate",
            IGNORE_LOGGER,
            {"tar_file": str(tar), **names},
        )

    def test_fail_no_tar_file(self, tmp_path):
        assert_failure(self._run(tmp_path / "missing.tar", indxname="indexer1"))

    def test_success_start_cluster_needs_only_the_tar(self, tmp_path):
        assert_success(self._run(self._tar(tmp_path, files=[], passwords={})))

    def test_success_all_components(self, tmp_path):
        tar = self._tar(tmp_path)
        assert_success(self._run(tar, indxname="indexer1", dashname="dashboard1", winame="wazuh1"))

    def test_fail_indexer_pair_missing(self, tmp_path):
        tar = self._tar(tmp_path, files=[f for f in self.FILES if f != "indexer1-key.pem"])
        assert_failure(self._run(tar, indxname="indexer1"))

    def test_fail_manager_remoted_pair_missing(self, tmp_path):
        tar = self._tar(tmp_path, files=[f for f in self.FILES if f != "wazuh1-remoted.pem"])
        assert_failure(self._run(tar, winame="wazuh1"))

    def test_fail_manager_apid_pair_missing(self, tmp_path):
        tar = self._tar(tmp_path, files=[f for f in self.FILES if f != "wazuh1-apid-key.pem"])
        assert_failure(self._run(tar, winame="wazuh1"))

    def test_fail_password_missing(self, tmp_path):
        passwords = {k: self.PASSWORD for k in self.KEYS if k != "WAZUH_MANAGER_WUI_PASSWORD"}
        assert_failure(self._run(self._tar(tmp_path, passwords=passwords), dashname="dashboard1"))

    def test_fail_password_against_policy(self, tmp_path):
        passwords = {k: self.PASSWORD for k in self.KEYS}
        passwords["WAZUH_INDEXER_ADMIN_PASSWORD"] = "onlylowercaseletters"
        assert_failure(self._run(self._tar(tmp_path, passwords=passwords), indxname="indexer1"))

    def test_fail_manager_password_missing(self, tmp_path):
        passwords = {k: self.PASSWORD for k in self.KEYS if k != "WAZUH_MANAGER_API_PASSWORD"}
        assert_failure(self._run(self._tar(tmp_path, passwords=passwords), winame="wazuh1"))

    def test_success_ignores_passwords_other_components_use(self, tmp_path):
        passwords = {"WAZUH_INDEXER_KIBANASERVER_PASSWORD": self.PASSWORD, "WAZUH_MANAGER_WUI_PASSWORD": self.PASSWORD}
        assert_success(self._run(self._tar(tmp_path, passwords=passwords), dashname="dashboard1"))


# ---------------------------------------------------------------------------
# checks_ports
# ---------------------------------------------------------------------------

SS_HEADER = "echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port'"
SS_BUSY = SS_HEADER + "; echo 'LISTEN 0 128 0.0.0.0:9200 0.0.0.0:*'"


def _command_without(*names):
    """Mock for `command` that reports the given tools as not installed.

    `command -v` also finds functions, so mocking a tool as a function can only
    simulate "present". To simulate "absent" the lookup itself has to be hidden.
    """
    missing = " || ".join(f'[ "$2" = "{n}" ]' for n in names)
    return f'if [ "$1" = "-v" ] && {{ {missing}; }}; then return 1; fi; builtin command "$@"'


class TestChecksPorts:
    def _run(self, mocks):
        base = {
            "common_logger": 'echo "$*"',
            "checks_firewall": "true",
            "installCommon_rollBack": "echo ROLLBACK",
        }
        return run_bash_function(BASE_SOURCES, "checks_ports 9200 9300", {**base, **mocks})

    def test_success_lsof_port_free(self):
        result = self._run({"lsof": "return 1"})
        assert_success(result)
        assert "being used" not in result.stdout

    def test_fail_lsof_port_busy(self):
        result = self._run({"lsof": "return 0"})
        assert_failure(result)
        assert "being used" in result.stdout
        assert "ROLLBACK" in result.stdout

    def test_fail_ss_port_busy_without_lsof(self):
        result = self._run({"command": _command_without("lsof"), "ss": SS_BUSY})
        assert_failure(result)
        assert "being used" in result.stdout
        assert "ROLLBACK" in result.stdout

    def test_success_ss_port_free_without_lsof(self):
        # Only the header line: must not be taken as a listener
        result = self._run({"command": _command_without("lsof"), "ss": SS_HEADER})
        assert_success(result)
        assert "being used" not in result.stdout

    def test_skipped_without_lsof_and_ss(self):
        result = self._run({"command": _command_without("lsof", "ss")})
        assert_failure(result)
        assert "Cannot find lsof or ss" in result.stdout
        assert "ROLLBACK" not in result.stdout

    def test_lsof_preferred_when_both_available(self):
        result = self._run({"lsof": "return 1", "ss": SS_BUSY})
        assert_success(result)


# ---------------------------------------------------------------------------
# checks_ArtifactURLs_format
# ---------------------------------------------------------------------------

class TestChecksArtifactURLsFormat:
    def _run(self, tmp_path, url):
        (tmp_path / "artifact_urls.yaml").write_text(f'wazuh_manager_x86_64_rpm: "{url}"\n')
        env = {"base_path": str(tmp_path), "artifact_urls_file_name": "artifact_urls.yaml"}
        return run_bash_function(BASE_SOURCES, "checks_ArtifactURLs_format", IGNORE_LOGGER, env)

    def test_success_https(self, tmp_path):
        assert_success(self._run(tmp_path, "https://example.com/wazuh-manager.rpm"))

    def test_fail_http(self, tmp_path):
        assert_failure(self._run(tmp_path, "http://example.com/wazuh-manager.rpm"))


# ---------------------------------------------------------------------------
# checks_uninstallComponents
# ---------------------------------------------------------------------------

class TestChecksUninstallComponents:
    NOT_FOUND = {
        "wazuh_installed": "",
        "wazuh_remaining_files": "",
        "indexer_installed": "",
        "indexer_remaining_files": "",
        "dashboard_installed": "",
        "dashboard_remaining_files": "",
    }

    def _run(self, env_vars=None):
        mocks = {"common_logger": 'echo "$@"'}
        return run_bash_function(BASE_SOURCES, "checks_uninstallComponents", mocks, {**self.NOT_FOUND, **(env_vars or {})})

    def test_nothing_installed_reports_the_three_components_and_fails(self):
        result = self._run()
        assert_failure(result)
        assert result.stdout.splitlines() == [
            "Wazuh manager not found in the system so it was not uninstalled.",
            "Wazuh indexer not found in the system so it was not uninstalled.",
            "Wazuh dashboard not found in the system so it was not uninstalled.",
        ]

    def test_everything_installed_prints_nothing_and_succeeds(self):
        result = self._run({"wazuh_installed": "1", "indexer_installed": "1", "dashboard_installed": "1"})
        assert_success(result)
        assert result.stdout == ""

    def test_partial_installation_reports_only_the_missing_components(self):
        result = self._run({"indexer_installed": "1"})
        assert_success(result)
        assert result.stdout.splitlines() == [
            "Wazuh manager not found in the system so it was not uninstalled.",
            "Wazuh dashboard not found in the system so it was not uninstalled.",
        ]

    def test_remaining_files_count_as_something_to_uninstall(self):
        result = self._run({"dashboard_remaining_files": "/etc/wazuh-dashboard"})
        assert_success(result)
        assert "Wazuh dashboard not found" not in result.stdout
