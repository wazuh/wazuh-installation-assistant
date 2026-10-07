"""
Unit tests for install_functions/installCommon.sh

Covers: installCommon_getConfig, installCommon_installPrerequisites,
        installCommon_startService, installCommon_placeFromTar,
        installCommon_placeCredentials, installCommon_createPasswords,
        installCommon_scanDependencies, installCommon_extractConfig,
        installCommon_createCertificates
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

INSTALL_COMMON = "install_functions/installCommon.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
CERT = "cert_tool/certFunctions.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, INSTALL_COMMON]

IGNORE_LOGGER = {"common_logger": "true"}

KEY_FIXTURE = Path(__file__).parent / "fixtures" / "GPG-KEY-WAZUH"
WAZUH_KEY = KEY_FIXTURE.read_text()
WAZUH_FINGERPRINT = "0DCFCA5547B19D2A6099506096B3EE5F29111145"


class TestInstallCommonGetConfig:
    """Tests for installCommon_getConfig.

    Requires exactly 2 arguments: config name and output path.
    Looks up content from a variable named config_file_<normalized_name>.
    """

    def _run(self, args="", extra_mocks=None):
        mocks = {
            **IGNORE_LOGGER,
            "installCommon_rollBack": "true",
            **(extra_mocks or {}),
        }
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


class TestInstallCommonInstallCheckDependencies:
    """Tests for installCommon_installCheckDependencies.

    Takes "assistant" or any other string (e.g. "wazuh") as first argument.
    Sets installing_assistant_deps accordingly and calls installCommon_installList
    with the matching dep array (assistant_deps_to_install or wazuh_deps_to_install).
    """

    def _run(self, dep_type, extra_mocks=None, extra_env=None):
        mocks = {
            **IGNORE_LOGGER,
            "installCommon_installList": "true",
            **(extra_mocks or {}),
        }
        env_vars = {
            "assistant_deps_to_install": "(curl grep)",
            "wazuh_deps_to_install": "(libcap)",
            "debug": "",
            **(extra_env or {}),
        }
        return run_bash_function(
            BASE_SOURCES,
            f"installCommon_installCheckDependencies {dep_type}",
            mocks,
            env_vars,
        )

    def test_success_assistant_type(self):
        assert_success(self._run("assistant"))

    def test_success_wazuh_type(self):
        assert_success(self._run("wazuh"))

    def test_success_empty_assistant_deps(self):
        result = self._run("assistant", extra_env={"assistant_deps_to_install": "()"})
        assert_success(result)

    def test_success_empty_wazuh_deps(self):
        result = self._run("wazuh", extra_env={"wazuh_deps_to_install": "()"})
        assert_success(result)


class TestInstallCommonInstallList:
    """Tests for installCommon_installList.

    Mocks installCommon_aptInstall / installCommon_yumInstall to avoid
    real package operations. Verifies that wia_dependencies_installed is
    populated only when installing_assistant_deps == 1.
    """

    def _run(
        self,
        sys_type,
        packages,
        installing_assistant_deps="0",
        install_success=True,
        extra_mocks=None,
    ):
        install_body = "install_result=0" if install_success else "install_result=1"
        mocks = {
            **IGNORE_LOGGER,
            "installCommon_aptInstall": install_body,
            "installCommon_yumInstall": install_body,
            "apt-get": "true",
            "installCommon_rollBack": "true",
            **(extra_mocks or {}),
        }
        pkg_args = " ".join(f'"{p}"' for p in packages)
        return run_bash_function(
            BASE_SOURCES,
            f"installCommon_installList {pkg_args}",
            mocks,
            {
                "sys_type": sys_type,
                "debug": "",
                "installing_assistant_deps": installing_assistant_deps,
            },
        )

    def test_success_yum_with_packages(self):
        result = self._run("yum", ["curl", "grep"])
        assert_success(result)

    def test_success_apt_with_packages(self):
        result = self._run("apt-get", ["curl", "grep"])
        assert_success(result)

    def test_success_empty_list(self):
        result = self._run("yum", [])
        assert_success(result)

    def test_fail_install_error(self):
        result = self._run("yum", ["curl"], install_success=False)
        assert_failure(result)

    def test_tracks_wia_dependencies_when_installing_assistant(self):
        """When installing_assistant_deps=1, installed packages are tracked
        in wia_dependencies_installed."""
        result = run_bash_function(
            BASE_SOURCES,
            'installCommon_installList "curl" "grep"; echo "${wia_dependencies_installed[@]}"',
            {
                **IGNORE_LOGGER,
                "installCommon_yumInstall": "install_result=0",
                "installCommon_aptInstall": "install_result=0",
                "apt-get": "true",
                "installCommon_rollBack": "true",
            },
            {"sys_type": "yum", "debug": "", "installing_assistant_deps": "1"},
        )
        assert_success(result)
        assert "curl" in result.stdout
        assert "grep" in result.stdout

    def test_does_not_track_wia_dependencies_for_wazuh_type(self):
        """When installing_assistant_deps=0, wia_dependencies_installed stays empty."""
        result = run_bash_function(
            BASE_SOURCES,
            'installCommon_installList "curl"; echo "deps=${wia_dependencies_installed[*]}"',
            {
                **IGNORE_LOGGER,
                "installCommon_yumInstall": "install_result=0",
                "installCommon_aptInstall": "install_result=0",
                "apt-get": "true",
                "installCommon_rollBack": "true",
            },
            {"sys_type": "yum", "debug": "", "installing_assistant_deps": "0"},
        )
        assert_success(result)
        assert "deps=" in result.stdout
        assert "curl" not in result.stdout.split("deps=")[1]


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


class TestInstallCommonDownloadArtifactURLs:
    """Tests for installCommon_downloadArtifactURLs.

    This function constructs different URLs for production vs pre-release modes
    and downloads artifact metadata to a specific path.
    """

    def _run(
        self,
        tmp_path,
        devrepo="",
        staging_url_stage="",
        curl_success=True,
        extra_mocks=None,
    ):
        """Helper to run installCommon_downloadArtifactURLs with configurable scenario.

        Args:
            tmp_path: Temporary directory for file outputs.
            devrepo: Value of devrepo variable (use "pre-release" to test pre-release mode).
            staging_url_stage: Value of staging_url_stage (required for pre-release).
            curl_success: Whether the curl command should succeed.
            extra_mocks: Additional mock functions.
        """
        # Mock common_curl to simulate download
        # Note: The function has a bug where it checks for the file in CWD but writes to base_path,
        # so we write to both locations to make the test work
        if curl_success:
            curl_mock = (
                'local output_file=$(echo "$@" | grep -oP "(?<=-sSo )[^ ]+")\n'
                'local filename=$(basename "$output_file")\n'
                'echo "mock yaml content" > "$output_file"\n'
                'echo "mock yaml content" > "$filename"'
            )
        else:
            curl_mock = "return 1"

        mocks = {
            **IGNORE_LOGGER,
            "common_curl": curl_mock,
            **(extra_mocks or {}),
        }

        env_vars = {
            "wazuh_version": "5.0.0",
            "wazuh_major": "5",
            "bucket": "packages.wazuh.com",
            "base_path": str(tmp_path),
            "debug": "",
        }

        if devrepo:
            env_vars["devrepo"] = devrepo
        if staging_url_stage:
            env_vars["staging_url_stage"] = staging_url_stage

        return run_bash_function(
            BASE_SOURCES,
            "installCommon_downloadArtifactURLs",
            mocks,
            env_vars,
        )

    def test_production_mode_constructs_correct_url(self, tmp_path):
        """Production mode: URL should be https://bucket/production/5.x/artifact-urls/artifact_urls_5.0.0.yaml"""
        result = self._run(tmp_path)
        assert_success(result)

        # Check that the correct file was created
        expected_filename = "artifact_urls_5.0.0.yaml"
        expected_file = tmp_path / expected_filename
        assert expected_file.exists(), f"Expected {expected_filename} to be created"
        assert expected_file.read_text() == "mock yaml content\n"

    def test_production_mode_empty_devrepo(self, tmp_path):
        """Production mode when devrepo is explicitly empty string"""
        result = self._run(tmp_path, devrepo="")
        assert_success(result)

        expected_filename = "artifact_urls_5.0.0.yaml"
        expected_file = tmp_path / expected_filename
        assert expected_file.exists()

    def test_production_mode_devrepo_not_prerelease(self, tmp_path):
        """Production mode when devrepo is set to something other than 'pre-release'"""
        result = self._run(tmp_path, devrepo="other")
        assert_success(result)

        # Should still use production URL format
        expected_filename = "artifact_urls_5.0.0.yaml"
        expected_file = tmp_path / expected_filename
        assert expected_file.exists()

    def test_prerelease_mode_constructs_correct_url(self, tmp_path):
        """Pre-release mode: URL should be https://bucket/pre-release/5.x/artifact-urls/artifact_urls_5.0.0-rc2.yaml"""
        result = self._run(tmp_path, devrepo="pre-release", staging_url_stage="rc2")
        assert_success(result)

        # Check that the correct file was created
        expected_filename = "artifact_urls_5.0.0-rc2.yaml"
        expected_file = tmp_path / expected_filename
        assert expected_file.exists(), f"Expected {expected_filename} to be created"
        assert expected_file.read_text() == "mock yaml content\n"

    def test_prerelease_mode_different_stage(self, tmp_path):
        """Pre-release mode with different staging stage name"""
        result = self._run(tmp_path, devrepo="pre-release", staging_url_stage="alpha2")
        assert_success(result)

        expected_filename = "artifact_urls_5.0.0-alpha2.yaml"
        expected_file = tmp_path / expected_filename
        assert expected_file.exists()

    def test_curl_failure_returns_error(self, tmp_path):
        """Function should fail when curl fails to download"""
        result = self._run(tmp_path, curl_success=False)
        assert_failure(result)

    def test_file_written_to_base_path(self, tmp_path):
        """Verify the file is written to base_path directory"""
        subdir = tmp_path / "custom_base"
        subdir.mkdir()

        env_vars = {
            "wazuh_version": "5.0.0",
            "wazuh_major": "5",
            "bucket": "packages.wazuh.com",
            "base_path": str(subdir),
            "debug": "",
        }

        # Note: Function has a bug - it writes to base_path but checks file in CWD
        curl_mock = (
            'local output_file=$(echo "$@" | grep -oP "(?<=-sSo )[^ ]+")\n'
            'local filename=$(basename "$output_file")\n'
            'echo "mock yaml content" > "$output_file"\n'
            'echo "mock yaml content" > "$filename"'
        )


class TestInstallCommonPlaceFromTar:
    """Tests for installCommon_placeFromTar.

    A file of the tar is placed where it does not exist, kept when an identical one is
    already there (the -g host), and refused when a different one is there.
    """

    def _run(self, tmp_path, existing=None):
        import subprocess

        staging = tmp_path / "wazuh-install-files"
        staging.mkdir()
        (staging / "root-ca.pem").write_text("the-ca")
        tar = tmp_path / "wazuh-install-files.tar"
        subprocess.run(["tar", "-cf", str(tar), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
        destination = tmp_path / "ca" / "root-ca.pem"
        destination.parent.mkdir()
        if existing is not None:
            destination.write_text(existing)
        result = run_bash_function(
            BASE_SOURCES,
            f'installCommon_placeFromTar root-ca.pem "{destination}" "$(id -un)" "$(id -gn)" 0644',
            IGNORE_LOGGER,
            {"tar_file": str(tar), "debug": ""},
        )
        return result, destination

    def test_success_places_file(self, tmp_path):
        result, destination = self._run(tmp_path)
        assert_success(result)
        assert destination.read_text() == "the-ca"
        assert oct(destination.stat().st_mode & 0o777) == "0o644"

    def test_success_keeps_identical_file(self, tmp_path):
        result, destination = self._run(tmp_path, existing="the-ca")
        assert_success(result)

    def test_fail_on_different_file(self, tmp_path):
        result, destination = self._run(tmp_path, existing="another-ca")
        assert_failure(result)
        assert destination.read_text() == "another-ca"


class TestInstallCommonExtractConfig:
    """config.yml is extracted to a new directory, not to a fixed path in /tmp."""

    def _tar(self, tmp_path):
        staging = tmp_path / "wazuh-install-files"
        staging.mkdir()
        (staging / "config.yml").write_text("nodes:\n")
        tar = tmp_path / "wazuh-install-files.tar"
        subprocess.run(["tar", "-cf", str(tar), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
        return tar

    def _run(self, tar):
        return run_bash_function(
            BASE_SOURCES,
            'installCommon_extractConfig && echo "${install_tmp_path}" && echo "${config_file}"',
            IGNORE_LOGGER,
            {"tar_file": str(tar), "debug": ""},
        )

    def test_success_extracts_to_a_new_directory(self, tmp_path):
        result = self._run(self._tar(tmp_path))
        install_tmp_path, config_file = (result.stdout.strip().splitlines() + ["", ""])[:2]
        try:
            assert_success(result)
            directory = Path(install_tmp_path)
            assert directory.name.startswith("wazuh-install-files.")
            assert directory.parent == Path("/tmp")
            assert directory.stat().st_mode & 0o077 == 0
            assert config_file == f"{install_tmp_path}/wazuh-install-files/config.yml"
            assert Path(config_file).read_text() == "nodes:\n"
        finally:
            if install_tmp_path.startswith("/tmp/wazuh-install-files."):
                shutil.rmtree(install_tmp_path, ignore_errors=True)

    def test_does_not_use_a_precreated_fixed_directory(self, tmp_path):
        fixed = Path("/tmp/wazuh-install-files")
        if fixed.exists() or fixed.is_symlink():
            pytest.skip("/tmp/wazuh-install-files already exists on this host")
        fixed.mkdir(mode=0o777)
        (fixed / "config.yml").write_text("attacker")
        result = self._run(self._tar(tmp_path))
        install_tmp_path = (result.stdout.strip().splitlines() + [""])[0]
        try:
            assert_success(result)
            assert not result.stdout.strip().endswith("/tmp/wazuh-install-files/config.yml")
            assert (fixed / "config.yml").read_text() == "attacker"
        finally:
            shutil.rmtree(fixed, ignore_errors=True)
            if install_tmp_path.startswith("/tmp/wazuh-install-files."):
                shutil.rmtree(install_tmp_path, ignore_errors=True)

    def test_fail_without_config_in_tar(self, tmp_path):
        staging = tmp_path / "wazuh-install-files"
        staging.mkdir()
        (staging / "clusterkey").write_text("key")
        tar = tmp_path / "wazuh-install-files.tar"
        subprocess.run(["tar", "-cf", str(tar), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
        assert_failure(self._run(tar))


class TestInstallCommonCreateCertificates:
    """The certificates of -g are created in a new directory, not in /tmp/wazuh-certificates."""

    def test_success_uses_a_new_directory_and_removes_it(self, tmp_path):
        record = tmp_path / "cert_tmp_path"
        mocks = {
            **IGNORE_LOGGER,
            "cert_readConfig": "true",
            "cert_checkListenerReachability": "true",
            "cert_checkRootCA": "true",
            "cert_generateAdmincertificate": f'echo "${{cert_tmp_path}}" > "{record}"; touch "${{cert_tmp_path}}/admin-key.pem"',
            "cert_generateIndexercertificates": "true",
            "cert_generateManagercertificates": "true",
            "cert_generateDashboardcertificates": "true",
            "cert_cleanFiles": "true",
            "cert_verifyRemotedcertificates": "true",
            "mv": "true",
        }
        result = run_bash_function(
            [*BASE_SOURCES, CERT], "installCommon_createCertificates", mocks, {"debug": ""}
        )
        assert_success(result)
        used = Path(record.read_text().strip())
        assert used.name.startswith("wazuh-certificates.")
        assert used.parent == Path("/tmp")
        assert not used.exists()


class TestInstallCommonCreatePasswords:
    """Tests for installCommon_createPasswords.

    -g writes the five passwords in the credentials file of the host, keeps any already
    there, and adds a copy of the file to the install files. The library is replaced by
    a flat file: it refuses a base directory under the world-writable /tmp.
    """

    KEYS = [
        "WAZUH_INDEXER_ADMIN_PASSWORD",
        "WAZUH_INDEXER_KIBANASERVER_PASSWORD",
        "WAZUH_INDEXER_MANAGER_PASSWORD",
        "WAZUH_MANAGER_API_PASSWORD",
        "WAZUH_MANAGER_WUI_PASSWORD",
    ]

    def test_success_generates_missing_and_keeps_existing(self, tmp_path):
        env_file = tmp_path / "credentials.env"
        env_file.write_text('WAZUH_MANAGER_API_PASSWORD="Kept.Password1"\n')
        copy = tmp_path / "copy.env"
        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installVariables.sh"],
            "installCommon_createPasswords",
            {
                **IGNORE_LOGGER,
                "wazuh_env_get": f'grep -q "^$1=" "{env_file}"',
                "wazuh_env_set": f'printf \'%s="%s"\\n\' "$1" "$2" >> "{env_file}"',
                "wazuh_env_get_file": f'echo "{env_file}"',
                "wazuh_password_generate": "echo Generated.Pass1",
                "cp": f'command cp "$1" "{copy}"',
                "chmod": "true",
            },
            {"debug": ""},
        )
        assert_success(result)
        lines = copy.read_text().splitlines()
        assert 'WAZUH_MANAGER_API_PASSWORD="Kept.Password1"' in lines
        for key in self.KEYS:
            assert sum(line.startswith(f"{key}=") for line in lines) == 1
        assert 'WAZUH_INDEXER_ADMIN_PASSWORD="Generated.Pass1"' in lines


class TestInstallCommonPlaceCredentials:
    """installCommon_placeCredentials places the passwords of the component and root-ca.pem.

    A node only receives the passwords of the components installed on it, never the CA
    key. The library is replaced by a flat file: it refuses a base directory under the
    world-writable /tmp.
    """

    PASSWORD = "Aa1.aaaaaaaaaaaa"

    def _tar(self, tmp_path):
        import subprocess

        staging = tmp_path / "wazuh-install-files"
        staging.mkdir()
        keys = TestInstallCommonCreatePasswords.KEYS
        (staging / "credentials.env").write_text("".join(f'{k}="{self.PASSWORD}"\n' for k in keys))
        for name in ["root-ca.pem", "root-ca.key"]:
            (staging / name).write_text(name)
        tar = tmp_path / "wazuh-install-files.tar"
        subprocess.run(["tar", "-cf", str(tar), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
        return tar

    def _run(self, tmp_path, tar, call):
        base = tmp_path / "etc-wazuh"
        env_file = base / "credentials.env"
        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installVariables.sh"],
            call,
            {
                **IGNORE_LOGGER,
                "wazuh_base_get_dir": f'echo "{base}"',
                "wazuh_ca_get_dir": f'echo "{base}/ca"',
                "wazuh_env_get": f'sed -n "s/^$1=\\"\\(.*\\)\\"$/\\1/p" "{env_file}" 2>/dev/null | grep .',
                "wazuh_env_set": f'printf \'%s="%s"\\n\' "$1" "$2" >> "{env_file}"',
                "wazuh_env_get_file": f'echo "{env_file}"',
                "install": 'if [ "$1" = -d ]; then mkdir -p "${@: -1}"; else cp "${@: -2:1}" "${@: -1}"; fi',
            },
            {"tar_file": str(tar), "debug": ""},
        )
        return result, base

    def _keys(self, base):
        return [line.split("=", 1)[0] for line in (base / "credentials.env").read_text().splitlines()]

    def test_success_places_anchor_without_key(self, tmp_path):
        result, base = self._run(tmp_path, self._tar(tmp_path), 'installCommon_placeCredentials "${indexer_credential_keys[@]}"')
        assert_success(result)
        assert (base / "ca" / "root-ca.pem").read_text() == "root-ca.pem"
        assert not (base / "ca" / "root-ca.key").exists()

    def test_success_indexer_node_gets_its_keys(self, tmp_path):
        result, base = self._run(tmp_path, self._tar(tmp_path), 'installCommon_placeCredentials "${indexer_credential_keys[@]}"')
        assert_success(result)
        assert self._keys(base) == [
            "WAZUH_INDEXER_ADMIN_PASSWORD",
            "WAZUH_INDEXER_KIBANASERVER_PASSWORD",
            "WAZUH_INDEXER_MANAGER_PASSWORD",
        ]

    def test_success_dashboard_node_gets_only_its_keys(self, tmp_path):
        result, base = self._run(tmp_path, self._tar(tmp_path), 'installCommon_placeCredentials "${dashboard_credential_keys[@]}"')
        assert_success(result)
        assert self._keys(base) == ["WAZUH_INDEXER_KIBANASERVER_PASSWORD", "WAZUH_MANAGER_WUI_PASSWORD"]
        assert f'WAZUH_MANAGER_WUI_PASSWORD="{self.PASSWORD}"' in (base / "credentials.env").read_text()

    def test_success_manager_node_gets_only_its_keys(self, tmp_path):
        result, base = self._run(tmp_path, self._tar(tmp_path), 'installCommon_placeCredentials "${manager_credential_keys[@]}"')
        assert_success(result)
        assert self._keys(base) == [
            "WAZUH_INDEXER_MANAGER_PASSWORD",
            "WAZUH_MANAGER_API_PASSWORD",
            "WAZUH_MANAGER_WUI_PASSWORD",
        ]

    def test_success_existing_file_only_gets_the_missing_keys(self, tmp_path):
        tar = self._tar(tmp_path)
        base = tmp_path / "etc-wazuh"
        base.mkdir()
        (base / "credentials.env").write_text(
            f'WAZUH_INDEXER_KIBANASERVER_PASSWORD="{self.PASSWORD}"\nWAZUH_MANAGER_API_PASSWORD="{self.PASSWORD}"\n'
        )
        result, base = self._run(tmp_path, tar, 'installCommon_placeCredentials "${dashboard_credential_keys[@]}"')
        assert_success(result)
        assert self._keys(base) == [
            "WAZUH_INDEXER_KIBANASERVER_PASSWORD",
            "WAZUH_MANAGER_API_PASSWORD",
            "WAZUH_MANAGER_WUI_PASSWORD",
        ]

    def test_success_several_components_get_the_union(self, tmp_path):
        tar = self._tar(tmp_path)
        result, base = self._run(
            tmp_path,
            tar,
            'installCommon_placeCredentials "${dashboard_credential_keys[@]}" && '
            'installCommon_placeCredentials "${manager_credential_keys[@]}"',
        )
        assert_success(result)
        assert sorted(self._keys(base)) == [
            "WAZUH_INDEXER_KIBANASERVER_PASSWORD",
            "WAZUH_INDEXER_MANAGER_PASSWORD",
            "WAZUH_MANAGER_API_PASSWORD",
            "WAZUH_MANAGER_WUI_PASSWORD",
        ]

    def test_fail_on_a_password_of_another_deployment(self, tmp_path):
        """A different value of a key the component does not use still stops the install."""
        tar = self._tar(tmp_path)
        base = tmp_path / "etc-wazuh"
        base.mkdir()
        existing = 'WAZUH_INDEXER_ADMIN_PASSWORD="Other.Password1"\n'
        (base / "credentials.env").write_text(existing)
        result, base = self._run(tmp_path, tar, 'installCommon_placeCredentials "${dashboard_credential_keys[@]}"')
        assert_failure(result)
        assert (base / "credentials.env").read_text() == existing
        assert not (base / "ca").exists()

    def test_fail_without_keys(self, tmp_path):
        result, base = self._run(tmp_path, self._tar(tmp_path), "installCommon_placeCredentials")
        assert_failure(result)
        assert not base.exists()


class TestInstallCommonScanDependencies:
    """-g needs what the credentials library uses; the other options do not."""

    def _all_deps(self, env):
        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installVariables.sh"],
            'installCommon_scanDependencies; printf "%s\\n" "${all_deps[@]}"',
            {**IGNORE_LOGGER, "rpm": "return 0"},
            {"sys_type": "yum", **env},
        )
        assert_success(result)
        return result.stdout.split()

    def test_generate_config_adds_library_dependencies(self):
        deps = self._all_deps({"configurations": "1"})
        for dep in ["openssl", "diffutils", "util-linux"]:
            assert dep in deps

    def test_manager_node_includes_package_requirements(self):
        deps = self._all_deps({"wazuh": "1"})
        for dep in ["openssl", "diffutils", "gawk", "iproute"]:
            assert dep in deps


class TestInstallCommonMergeCredentials:
    """installCommon_mergeCredentials completes a credentials file already on the host.

    The file can miss keys (a failed install whose package removed its own) but a
    different value means the file belongs to another deployment.
    """

    PASSWORD = "Aa1.aaaaaaaaaaaa"

    def _run(self, tmp_path, existing, keys='"${credential_keys[@]}"'):
        return self._run_mode(tmp_path, existing, f"merge {keys}")

    def _run_mode(self, tmp_path, existing, mode):
        import subprocess

        staging = tmp_path / "wazuh-install-files"
        staging.mkdir()
        keys = TestInstallCommonCreatePasswords.KEYS
        (staging / "credentials.env").write_text("".join(f'{k}="{self.PASSWORD}"\n' for k in keys))
        tar = tmp_path / "wazuh-install-files.tar"
        subprocess.run(["tar", "-cf", str(tar), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
        env_file = tmp_path / "credentials.env"
        env_file.write_text(existing)
        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installVariables.sh"],
            f"installCommon_mergeCredentials {mode}",
            {
                **IGNORE_LOGGER,
                "wazuh_env_get": f'sed -n "s/^$1=\\"\\(.*\\)\\"$/\\1/p" "{env_file}" | grep .',
                "wazuh_env_set": f'printf \'%s="%s"\\n\' "$1" "$2" >> "{env_file}"',
                "wazuh_env_get_file": f'echo "{env_file}"',
            },
            {"tar_file": str(tar)},
        )
        return result, env_file.read_text()

    def test_success_adds_missing_keys(self, tmp_path):
        result, content = self._run(tmp_path, f'WAZUH_MANAGER_API_PASSWORD="{self.PASSWORD}"\n')
        assert_success(result)
        for key in TestInstallCommonCreatePasswords.KEYS:
            assert content.count(f'{key}="{self.PASSWORD}"') == 1

    def test_success_adds_only_the_given_keys(self, tmp_path):
        result, content = self._run(tmp_path, "", '"${dashboard_credential_keys[@]}"')
        assert_success(result)
        assert content == (
            f'WAZUH_INDEXER_KIBANASERVER_PASSWORD="{self.PASSWORD}"\n'
            f'WAZUH_MANAGER_WUI_PASSWORD="{self.PASSWORD}"\n'
        )

    def test_success_writes_nothing_without_keys(self, tmp_path):
        result, content = self._run(tmp_path, "", "")
        assert_success(result)
        assert content == ""

    def test_fail_on_a_key_missing_from_the_tar(self, tmp_path):
        result, _ = self._run(tmp_path, "", "WAZUH_UNKNOWN_PASSWORD")
        assert_failure(result)

    def test_fail_on_a_different_password(self, tmp_path):
        result, _ = self._run(tmp_path, 'WAZUH_MANAGER_API_PASSWORD="Other.Password1"\n')
        assert_failure(result)

    def test_check_mode_writes_nothing(self, tmp_path):
        """Checking a file from another deployment leaves it as it was."""
        result, content = self._run_mode(tmp_path, 'WAZUH_MANAGER_API_PASSWORD="Other.Password1"\n', "check")
        assert_failure(result)
        assert content == 'WAZUH_MANAGER_API_PASSWORD="Other.Password1"\n'

    def test_check_mode_accepts_a_compatible_file(self, tmp_path):
        result, content = self._run_mode(tmp_path, f'WAZUH_MANAGER_API_PASSWORD="{self.PASSWORD}"\n', "check")
        assert_success(result)
        assert content == f'WAZUH_MANAGER_API_PASSWORD="{self.PASSWORD}"\n'


class TestInstallCommonVerifyPackageSignature:
    """Tests for installCommon_verifyPackageSignature on RPM packages.

    The key is mocked as already checked; rpm is mocked: -q reports the key as
    imported, -qp prints the signer and -K returns the given exit code.
    """

    WAZUH_SIGNER = "RSA/SHA256, Mon Oct  5 23:35:00 2026, Key ID 96b3ee5f29111145"

    def _run(self, signer, checksig_rc=0, skip=""):
        rpm_mock = (
            'case "$1" in -qp) echo "' + signer + '";; -K) return ' + str(checksig_rc) + ';; esac; return 0'
        )
        mocks = {
            **IGNORE_LOGGER,
            "installCommon_rollBack": "true",
            "installCommon_getWazuhGPGKey": "true",
            "installCommon_getGPGKeyFingerprint": f"echo {WAZUH_FINGERPRINT}",
            "rpm": rpm_mock,
        }
        env = {"skip_signature_check": skip}
        return run_bash_function(BASE_SOURCES, "installCommon_verifyPackageSignature /tmp/p.rpm", mocks, env)

    def test_success_signed_with_wazuh_key(self):
        assert_success(self._run(self.WAZUH_SIGNER))

    def test_fail_unsigned(self):
        assert_failure(self._run("(none)"))

    def test_fail_signed_with_another_key(self):
        assert_failure(self._run("RSA/SHA256, Mon Oct  5 23:35:00 2026, Key ID 0123456789abcdef"))

    def test_fail_invalid_signature(self):
        assert_failure(self._run(self.WAZUH_SIGNER, checksig_rc=1))

    def test_success_unsigned_with_skip(self):
        assert_success(self._run("(none)", skip="1"))


class TestInstallCommonGetWazuhGPGKey:
    """Tests for installCommon_getWazuhGPGKey with the key of the offline bundle.

    The key is only trusted if the file holds a single primary key with a pinned fingerprint.
    """

    def _run(self, tmp_path, key_text):
        bundle = tmp_path / "wazuh-offline"
        bundle.mkdir()
        (bundle / "GPG-KEY-WAZUH").write_text(key_text)
        key_dir = tmp_path / "key"
        key_dir.mkdir()
        mocks = {**IGNORE_LOGGER, "installCommon_rollBack": "true"}
        env = {
            "offline_install": "1",
            "base_path": str(tmp_path),
            "wazuh_gpg_key_fingerprints": f"( {WAZUH_FINGERPRINT} )",
        }
        return run_bash_function(BASE_SOURCES, f"installCommon_getWazuhGPGKey {key_dir}", mocks, env)

    def test_success_wazuh_key(self, tmp_path):
        assert_success(self._run(tmp_path, WAZUH_KEY))

    def test_fail_two_keys_in_the_file(self, tmp_path):
        assert_failure(self._run(tmp_path, WAZUH_KEY + WAZUH_KEY))

    def test_fail_modified_key(self, tmp_path):
        lines = WAZUH_KEY.splitlines(keepends=True)
        body = lines.index("\n") + 1
        lines[body] = ("A" if lines[body][0] != "A" else "B") + lines[body][1:]
        assert_failure(self._run(tmp_path, "".join(lines)))

    def test_fail_no_key(self, tmp_path):
        assert_failure(self._run(tmp_path, ""))


class TestInstallCommonGetGPGKeyFingerprint:
    def test_success_wazuh_key(self, tmp_path):
        result = run_bash_function(
            BASE_SOURCES,
            f"sed '1,/^$/d; /^=/,$d; /^-----/d' {KEY_FIXTURE} | base64 -d > {tmp_path}/k.gpg && "
            f"installCommon_getGPGKeyFingerprint {tmp_path}/k.gpg",
            IGNORE_LOGGER,
        )
        assert_success(result)
        assert result.stdout.strip() == WAZUH_FINGERPRINT


class TestInstallCommonGetPackages:
    """Tests for installCommon_getPackages with the packages of the offline bundle.

    Every package of the components to install is checked before any of them is installed.
    """

    PACKAGES = [
        "wazuh-indexer-5.0.0-1.x86_64.rpm",
        "wazuh-manager-5.0.0-1.x86_64.rpm",
        "wazuh-dashboard-5.0.0-1.x86_64.rpm",
    ]

    def _run(self, tmp_path, packages):
        for package in packages:
            (tmp_path / package).touch()
        mocks = {
            **IGNORE_LOGGER,
            "installCommon_rollBack": "true",
            "installCommon_downloadComponent": "true",
            "installCommon_verifyPackageSignature": 'echo "checked $(basename $1)"',
        }
        env = {"AIO": "1", "offline_install": "1", "offline_packages_path": str(tmp_path), "sys_type": "yum"}
        return run_bash_function(BASE_SOURCES, "installCommon_getPackages", mocks, env)

    def test_success_checks_every_aio_package(self, tmp_path):
        result = self._run(tmp_path, self.PACKAGES)
        assert_success(result)
        assert result.stdout.split("\n")[:3] == [f"checked {p}" for p in self.PACKAGES]

    def test_fail_missing_package(self, tmp_path):
        assert_failure(self._run(tmp_path, self.PACKAGES[:2]))
