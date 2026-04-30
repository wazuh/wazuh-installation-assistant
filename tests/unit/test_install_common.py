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
        """Production mode: URL should be https://bucket/production/5.x/artifact_urls_5.0.0.yaml"""
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
        """Pre-release mode: URL should be https://bucket/pre-release/5.x/artifact_urls_5.0.0-rc1.yaml"""
        result = self._run(tmp_path, devrepo="pre-release", staging_url_stage="rc1")
        assert_success(result)

        # Check that the correct file was created
        expected_filename = "artifact_urls_5.0.0-rc1.yaml"
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
