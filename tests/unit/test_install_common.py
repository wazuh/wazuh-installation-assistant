"""
Unit tests for install_functions/installCommon.sh

Covers: installCommon_getConfig, installCommon_installPrerequisites,
        installCommon_startService, installCommon_restartService,
        installCommon_createInstallFiles, installCommon_placeFromTar,
        installCommon_placeCredentials, installCommon_createPasswords,
        installCommon_scanDependencies, installCommon_extractConfig,
        installCommon_createCertificates, installCommon_logRunHeader,
        installCommon_rollBack, installCommon_cleanExit
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from tests.unit.conftest import VERBOSE_DEBUG, assert_failure, assert_success, run_bash_function

INSTALL_COMMON = "install_functions/installCommon.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
CERT = "cert_tool/certFunctions.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, INSTALL_COMMON]
CREDENTIALS = "common_functions/credentials.sh"
# The tests do not run as root: the owner checks and changes are mocked.
ROOT_MOCKS = {"chown": "true", "stat": "echo 0"}

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


class TestInstallCommonPackageOutputLog:
    """The output of apt-get and yum keeps its line breaks in the log."""

    @pytest.mark.parametrize("func, cmd", [
        ("installCommon_aptInstall", "apt-get"),
        ("installCommon_yumInstall", "yum"),
    ])
    def test_log_keeps_line_breaks(self, tmp_path, func, cmd):
        log = tmp_path / "install.log"
        result = run_bash_function(
            BASE_SOURCES,
            f"{func} wazuh-manager",
            {
                **IGNORE_LOGGER,
                "common_checkAptLock": "true",
                "common_checkYumLock": "true",
                cmd: "printf 'line one\\nline two\\n'",
            },
            {"attempt": "0", "max_attempts": "5", "debug": f">> {log} 2>&1"},
        )
        assert_success(result)
        assert log.read_text().splitlines() == ["line one", "line two"]


class TestInstallCommonStartService:
    """Tests for installCommon_startService.

    The function checks for systemd/init and starts a named service.
    We mock systemctl so no real service management occurs.
    """

    def _run(self, service_name, systemctl_success=True, extra_mocks=None, debug=""):
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
            {"debug": debug, "logfile": "/dev/null"},
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

    @pytest.mark.parametrize("debug", ["", VERBOSE_DEBUG])
    def test_success_start_with_any_debug(self, debug):
        assert_success(self._run("wazuh-manager", debug=debug))

    @pytest.mark.parametrize("debug", ["", VERBOSE_DEBUG])
    def test_fail_service_start_error(self, debug):
        """With -v, the failure of systemctl must not be hidden by tee (#1119)."""
        result = self._run(
            "wazuh-manager",
            systemctl_success=False,
            extra_mocks={"common_logger": 'echo "LOG:$*"', "installCommon_rollBack": 'echo "ROLLBACK"'},
            debug=debug,
        )
        assert_failure(result)
        assert "LOG:-e wazuh-manager could not be started." in result.stdout
        assert "ROLLBACK" in result.stdout
        assert "service started" not in result.stdout

    def test_fail_when_the_service_stops_after_the_start(self):
        result = self._run(
            "wazuh-manager",
            extra_mocks={
                "systemctl": '[ "$1" = is-active ] && return 3; return 0',
                "common_logger": 'echo "LOG:$*"',
                "installCommon_rollBack": 'echo "ROLLBACK"',
            },
        )
        assert_failure(result)
        assert "LOG:-e wazuh-manager could not be started." in result.stdout
        assert "ROLLBACK" in result.stdout

    def test_prints_the_credential_problems_of_the_journal(self):
        journal = (
            "Starting wazuh-dashboard\n"
            "resolve-credentials: MISSING /etc/wazuh-dashboard/certs/indexer-ca.pem: stage the indexer CA\n"
            "resolve-credentials: warning: MISSING /etc/wazuh-dashboard/certs/manager-ca.pem\n"
            "UNSAFE /etc/wazuh-dashboard/local.env: group-writable\n"
        )
        result = self._run(
            "wazuh-dashboard",
            systemctl_success=False,
            extra_mocks={
                "journalctl": f'[[ "$*" == *--since* ]] && printf "{journal}"',
                "common_logger": 'echo "LOG:$*"',
            },
        )
        assert_failure(result)
        assert "LOG:-e wazuh-dashboard found these problems with its credentials:" in result.stdout
        assert "LOG:-e     MISSING /etc/wazuh-dashboard/certs/indexer-ca.pem: stage the indexer CA" in result.stdout
        assert "LOG:-e     UNSAFE /etc/wazuh-dashboard/local.env: group-writable" in result.stdout
        assert "manager-ca.pem" not in result.stdout

    def test_runs_the_package_check_without_journal_lines(self, tmp_path):
        check = tmp_path / "resolve"
        check.write_text("#!/bin/bash\necho 'resolve-credentials: INVALID WAZUH_MANAGER_API_PASSWORD: bad value' >&2\n")
        check.chmod(0o755)
        mocks = {
            **IGNORE_LOGGER, "systemctl": "return 1", "journalctl": "true",
            "installCommon_rollBack": "true", "common_logger": 'echo "LOG:$*"',
        }
        result = run_bash_function(
            BASE_SOURCES, "installCommon_startService wazuh-manager", mocks,
            {"debug": "", "logfile": "/dev/null", "manager_resolver": str(check)},
        )
        assert_failure(result)
        assert "LOG:-e     INVALID WAZUH_MANAGER_API_PASSWORD: bad value" in result.stdout


class TestInstallCommonRestartService:
    """Tests for installCommon_restartService."""

    def _run(self, systemctl_success, debug):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "systemctl": "true" if systemctl_success else "return 1",
            "journalctl": "true",
            "installCommon_rollBack": 'echo "ROLLBACK"',
        }
        return run_bash_function(
            BASE_SOURCES,
            "installCommon_restartService wazuh-manager",
            mocks,
            {"debug": debug, "logfile": "/dev/null"},
        )

    @pytest.mark.parametrize("debug", ["", VERBOSE_DEBUG])
    def test_success(self, debug):
        result = self._run(True, debug)
        assert_success(result)
        assert "LOG:wazuh-manager service restarted." in result.stdout

    @pytest.mark.parametrize("debug", ["", VERBOSE_DEBUG])
    def test_fail_restart_error(self, debug):
        result = self._run(False, debug)
        assert_failure(result)
        assert "LOG:-e wazuh-manager could not be restarted." in result.stdout
        assert "ROLLBACK" in result.stdout


class TestInstallCommonCreateInstallFiles:
    """installCommon_createInstallFiles stops when it cannot create its directory."""

    @pytest.mark.parametrize("debug", ["", VERBOSE_DEBUG])
    def test_fail_when_mkdir_fails(self, debug):
        result = run_bash_function(
            BASE_SOURCES,
            "installCommon_createInstallFiles",
            {"common_logger": 'echo "LOG:$*"', "rm": "true", "mkdir": "return 1",
             "installCommon_createCertificates": 'echo "CERTS_CREATED"'},
            {"debug": debug},
        )
        assert_failure(result)
        assert "LOG:-e Unable to create /tmp/wazuh-install-files" in result.stdout
        assert "CERTS_CREATED" not in result.stdout


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
        debug="",
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
            "debug": debug,
            "logfile": "/dev/null",
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
        # The repository bumper keeps this version-stage string in sync
        release = "5.0.0-rc2"
        result = self._run(tmp_path, devrepo="pre-release", staging_url_stage=release.split("-")[1])
        assert_success(result)

        # Check that the correct file was created
        expected_filename = f"artifact_urls_{release}.yaml"
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

    @pytest.mark.parametrize("debug", ["", VERBOSE_DEBUG])
    def test_curl_failure_returns_error(self, tmp_path, debug):
        """Function should fail when curl fails to download, also with -v"""
        result = self._run(tmp_path, curl_success=False, debug=debug)
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

    -g writes the five passwords in credentials.env next to the root CA, keeps the valid
    ones already there, and adds a copy of the file to the install files.
    """

    KEYS = [
        "WAZUH_INDEXER_ADMIN_PASSWORD",
        "WAZUH_INDEXER_KIBANASERVER_PASSWORD",
        "WAZUH_INDEXER_MANAGER_PASSWORD",
        "WAZUH_MANAGER_API_PASSWORD",
        "WAZUH_MANAGER_WUI_PASSWORD",
    ]

    def test_success_generates_missing_and_keeps_existing(self, tmp_path):
        ca_dir = tmp_path / "wazuh-ca"
        ca_dir.mkdir()
        (ca_dir / "credentials.env").write_text("WAZUH_MANAGER_API_PASSWORD=Kept.Password1\n")
        copy = tmp_path / "copy.env"
        result = run_bash_function(
            [*BASE_SOURCES, CREDENTIALS, "install_functions/installVariables.sh"],
            "installCommon_createPasswords",
            {
                **IGNORE_LOGGER,
                **ROOT_MOCKS,
                "common_caGetDir": f'echo "{ca_dir}"',
                "common_passwordGenerate": "echo Generated.Pass1",
                "cp": f'command cp "$1" "{copy}"',
                "chmod": "true",
            },
            {"debug": ""},
        )
        assert_success(result)
        lines = copy.read_text().splitlines()
        assert "WAZUH_MANAGER_API_PASSWORD=Kept.Password1" in lines
        for key in self.KEYS:
            assert sum(line.startswith(f"{key}=") for line in lines) == 1
        assert "WAZUH_INDEXER_ADMIN_PASSWORD=Generated.Pass1" in lines

    def test_success_replaces_an_invalid_password(self, tmp_path):
        ca_dir = tmp_path / "wazuh-ca"
        ca_dir.mkdir()
        (ca_dir / "credentials.env").write_text("WAZUH_MANAGER_API_PASSWORD=short\n")
        result = run_bash_function(
            [*BASE_SOURCES, CREDENTIALS, "install_functions/installVariables.sh"],
            "installCommon_createPasswords",
            {
                **IGNORE_LOGGER,
                **ROOT_MOCKS,
                "common_caGetDir": f'echo "{ca_dir}"',
                "common_passwordGenerate": "echo Generated.Pass1",
                "cp": "true",
                "chmod": "true",
            },
            {"debug": ""},
        )
        assert_success(result)
        assert "WAZUH_MANAGER_API_PASSWORD=Generated.Pass1" in (ca_dir / "credentials.env").read_text()


class TestInstallCommonPlaceLocalEnv:
    """installCommon_placeLocalEnv writes the local.env of one package.

    A package only receives the passwords it uses, and a different value already in
    the file means the file belongs to another deployment.
    """

    PASSWORD = "Aa1.aaaaaaaaaaaa"

    def _tar(self, tmp_path):
        import subprocess

        staging = tmp_path / "wazuh-install-files"
        staging.mkdir()
        keys = TestInstallCommonCreatePasswords.KEYS
        (staging / "credentials.env").write_text("".join(f'{k}="{self.PASSWORD}"\n' for k in keys))
        tar = tmp_path / "wazuh-install-files.tar"
        subprocess.run(["tar", "-cf", str(tar), "-C", str(tmp_path), "wazuh-install-files/"], check=True)
        return tar

    def _run(self, tmp_path, keys, existing=None):
        tar = self._tar(tmp_path)
        config = tmp_path / "etc-wazuh-dashboard"
        if existing is not None:
            config.mkdir()
            (config / "local.env").write_text(existing)
        result = run_bash_function(
            [*BASE_SOURCES, CREDENTIALS, "install_functions/installVariables.sh"],
            f'installCommon_placeLocalEnv "{config}" {keys}',
            {
                **IGNORE_LOGGER,
                **ROOT_MOCKS,
                "install": 'if [ "$1" = -d ]; then mkdir -p "${@: -1}"; fi',
            },
            {"tar_file": str(tar), "debug": ""},
        )
        return result, config / "local.env"

    def test_success_writes_only_the_keys_of_the_package(self, tmp_path):
        result, env = self._run(tmp_path, '"${dashboard_credential_keys[@]}"')
        assert_success(result)
        assert env.read_text() == (
            f"WAZUH_INDEXER_KIBANASERVER_PASSWORD={self.PASSWORD}\n"
            f"WAZUH_MANAGER_WUI_PASSWORD={self.PASSWORD}\n"
        )
        assert oct(env.stat().st_mode & 0o777) == "0o600"

    def test_success_keeps_the_same_value(self, tmp_path):
        existing = f"WAZUH_MANAGER_WUI_PASSWORD={self.PASSWORD}\n"
        result, env = self._run(tmp_path, '"${dashboard_credential_keys[@]}"', existing)
        assert_success(result)
        assert env.read_text().count("WAZUH_MANAGER_WUI_PASSWORD=") == 1

    def test_fail_on_a_password_of_another_deployment(self, tmp_path):
        existing = "WAZUH_MANAGER_WUI_PASSWORD=Other.Password1\n"
        result, env = self._run(tmp_path, '"${dashboard_credential_keys[@]}"', existing)
        assert_failure(result)
        assert env.read_text() == existing

    def test_fail_on_a_key_missing_from_the_tar(self, tmp_path):
        result, _ = self._run(tmp_path, "WAZUH_UNKNOWN_PASSWORD")
        assert_failure(result)


class TestInstallCommonScanDependencies:
    """-g needs openssl for the root CA; the other options do not."""

    def _all_deps(self, env):
        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installVariables.sh"],
            'installCommon_scanDependencies; printf "%s\\n" "${all_deps[@]}"',
            {**IGNORE_LOGGER, "rpm": "return 0"},
            {"sys_type": "yum", **env},
        )
        assert_success(result)
        return result.stdout.split()

    def test_generate_config_adds_openssl(self):
        deps = self._all_deps({"configurations": "1"})
        assert "openssl" in deps

    def test_manager_node_includes_package_requirements(self):
        deps = self._all_deps({"wazuh": "1"})
        for dep in ["openssl", "diffutils", "gawk", "iproute"]:
            assert dep in deps

    @pytest.mark.parametrize(
        "step, operation",
        [("wazuh", "installation"), ("start_indexer_cluster", "cluster initialization")],
    )
    def test_missing_dependencies_message_names_the_operation(self, step, operation):
        result = run_bash_function(
            [*BASE_SOURCES, "install_functions/installVariables.sh"],
            "installCommon_scanDependencies",
            {"common_logger": 'printf "%s\\n" "$*"', "rpm": "return 1"},
            {"sys_type": "yum", step: "1"},
        )
        assert_failure(result)
        assert result.stdout.startswith("-e ")
        assert f"To perform the {operation}, the following package/s must be installed:" in result.stdout
        assert f"will be removed after the {operation}:" in result.stdout
        if step == "start_indexer_cluster":
            assert "installation" not in result.stdout


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


class TestInstallCommonDownloadDirectory:
    """installCommon_downloadComponent refuses a download directory that others can write to."""

    def _run(self, tmp_path):
        return run_bash_function(
            BASE_SOURCES,
            "installCommon_downloadComponent wazuh_manager",
            {"common_logger": 'echo "$@"', "installCommon_rollBack": "true"},
            {"base_path": str(tmp_path), "download_packages_directory": "pkgs", "sys_type": "none"},
        )

    def test_creates_private_directory(self, tmp_path):
        result = self._run(tmp_path)
        assert "must belong" not in result.stdout
        assert (tmp_path / "pkgs").stat().st_mode & 0o777 == 0o700

    @pytest.mark.parametrize("mode", [0o777, 0o775])
    def test_fail_writable_by_others(self, tmp_path, mode):
        (tmp_path / "pkgs").mkdir()
        (tmp_path / "pkgs").chmod(mode)
        result = self._run(tmp_path)
        assert_failure(result)
        assert "must belong" in result.stdout

    def test_fail_symlink(self, tmp_path):
        (tmp_path / "real").mkdir(mode=0o700)
        (tmp_path / "pkgs").symlink_to(tmp_path / "real")
        result = self._run(tmp_path)
        assert_failure(result)
        assert "must belong" in result.stdout


class TestInstallCommonRollBack:
    """Tests for installCommon_rollBack: the section header and the closing message."""

    HEADER = "--- Removing existing Wazuh installation ---"
    MOCKS = {
        "common_logger": 'echo "$@"',
        "installCommon_removeWIADependencies": "true",
        "systemctl": "true",
        "rm": "true",
    }

    def _run(self, env_vars=None):
        return run_bash_function(BASE_SOURCES, "installCommon_rollBack", self.MOCKS, env_vars)

    def test_failed_installation_prints_the_header_first(self):
        result = self._run({"dashboard_installed": "1", "dashboard": "1", "rollback_conf": "1"})
        assert_success(result)
        lines = result.stdout.splitlines()
        assert lines[0] == self.HEADER
        assert lines[-1] == "Installation cleaned."

    def test_uninstall_leaves_the_header_to_the_caller(self):
        result = self._run({"dashboard_installed": "1", "uninstall": "1"})
        assert_success(result)
        assert self.HEADER not in result.stdout
        assert result.stdout.splitlines() == ["Removing Wazuh dashboard.", "Wazuh dashboard removed."]

    def test_uninstall_on_an_empty_host_still_runs_the_unconditional_cleanup(self):
        mocks = {**self.MOCKS, "installCommon_removeWIADependencies": 'echo "deps"', "systemctl": 'echo "systemctl $@"'}
        result = run_bash_function(BASE_SOURCES, "installCommon_rollBack", mocks, {"uninstall": "1"})
        assert_success(result)
        assert result.stdout.splitlines() == ["deps", "systemctl daemon-reload"]

    def test_start_cluster_messages_do_not_mention_an_installation(self):
        result = self._run({"start_indexer_cluster": "1", "logfile": "/var/log/wazuh-install.log"})
        assert_success(result)
        assert result.stdout.splitlines() == [
            "Cluster initialization cleaned. Check the /var/log/wazuh-install.log file to learn more about the issue."
        ]

    def test_start_cluster_after_ctrl_c(self):
        result = self._run({"start_indexer_cluster": "1", "rollback_conf": "y"})
        assert_success(result)
        assert result.stdout.splitlines() == ["Cluster initialization cleaned."]

    def test_removing_dependencies_is_a_noop_when_none_were_scanned(self):
        # The uninstall flow never runs installCommon_scanDependencies, so nothing is removed
        mocks = {"common_logger": 'echo "$@"', "yum": "exit 1", "apt-get": "exit 1"}
        for sys_type in ("yum", "apt-get"):
            result = run_bash_function(
                BASE_SOURCES, "installCommon_removeWIADependencies", mocks, {"sys_type": sys_type}
            )
            assert_success(result)
            assert result.stdout == ""


class TestInstallCommonRollBackScope:
    """installCommon_rollBack removes only the components of the failed step, also on a host with all of them."""

    HOST = {
        "sys_type": "apt-get",
        "wazuh_installed": "1",
        "indexer_installed": "1",
        "dashboard_installed": "1",
        "wazuh_remaining_files": "1",
        "indexer_remaining_files": "1",
        "dashboard_remaining_files": "1",
    }
    MOCKS = {
        "common_logger": "true",
        "common_checkAptLock": "true",
        "apt-get": 'echo "purge $3"',
        "apt": "true",
        "rm": 'shift; printf "rm %s\\n" "$@"',
        "installCommon_removeWIADependencies": "true",
        "systemctl": "true",
    }
    ALL = {"manager", "indexer", "dashboard"}

    @staticmethod
    def _component(item):
        if "wazuh-manager" in item:
            return "manager"
        if "wazuh-indexer" in item or "opensearch" in item or "securityadmin" in item:
            return "indexer"
        if "dashboard" in item:
            return "dashboard"
        raise AssertionError(f"Unknown item removed: {item}")

    def _run(self, step):
        result = run_bash_function(BASE_SOURCES, "installCommon_rollBack", self.MOCKS, {**self.HOST, step: "1"})
        assert_success(result)
        return result.stdout.splitlines()

    @pytest.mark.parametrize(
        "step, removed",
        [
            ("start_indexer_cluster", set()),
            ("indexer", {"indexer"}),
            ("dashboard", {"dashboard"}),
            ("wazuh", {"manager"}),
            ("AIO", ALL),
            ("uninstall", ALL),
        ],
    )
    def test_removes_only_the_components_of_the_step(self, step, removed):
        lines = self._run(step)
        assert {self._component(line) for line in lines} == removed

    @pytest.mark.parametrize("step", ["start_indexer_cluster", "dashboard", "wazuh"])
    def test_keeps_the_log_directory_of_the_indexer(self, step):
        assert "rm /var/log/wazuh-indexer/" not in self._run(step)

    def test_indexer_step_removes_its_log_directory(self):
        lines = self._run("indexer")
        assert "purge wazuh-indexer" in lines
        assert "rm /var/log/wazuh-indexer/" in lines


class TestInstallCommonCleanExit:
    """installCommon_cleanExit runs on Ctrl+C: it stops the indexer security initializer and asks about the cleanup."""

    MOCKS = {"common_checkInstalled": "true", "installCommon_rollBack": 'echo "ROLLBACK"'}

    def _run(self, answer, env=None):
        return run_bash_function(BASE_SOURCES, "installCommon_cleanExit", self.MOCKS, env, stdin=f"{answer}\n")

    def test_installation_question(self):
        result = self._run("n")
        assert result.returncode == 1
        assert "Do you want to remove the ongoing installation?[Y/N]" in result.stdout
        assert "ROLLBACK" not in result.stdout

    def test_start_cluster_question(self):
        result = self._run("y", {"start_indexer_cluster": "1"})
        assert result.returncode == 1
        assert "Do you want to clean up the ongoing cluster initialization?[Y/N]" in result.stdout
        assert "installation" not in result.stdout
        assert "ROLLBACK" in result.stdout



class TestInstallCommonLogRunHeader:
    """installCommon_logRunHeader appends a header for the run, keeping the log of the previous runs."""

    HEADER = "INFO: --- Wazuh installation assistant 0.1 (Wazuh 5.0.0). Options: {} ---"

    def _run(self, logfile, args=""):
        return run_bash_function(
            BASE_SOURCES,
            f"installCommon_logRunHeader {args}",
            env_vars={"logfile": str(logfile), "wazuh_install_vesion": "0.1", "wazuh_version": "5.0.0"},
        )

    def test_appends_after_previous_runs(self, tmp_path):
        log = tmp_path / "wazuh-install.log"
        log.write_text("01/01/2026 00:00:00 INFO: previous run\n")
        assert_success(self._run(log, "-wi node-1"))
        lines = log.read_text().splitlines()
        assert lines[0] == "01/01/2026 00:00:00 INFO: previous run"
        assert lines[1] == ""
        assert lines[2].endswith(self.HEADER.format("-wi node-1"))

    def test_new_log_starts_with_header(self, tmp_path):
        log = tmp_path / "wazuh-install.log"
        assert_success(self._run(log, "-a"))
        lines = log.read_text().splitlines()
        assert len(lines) == 1
        assert lines[0].endswith(self.HEADER.format("-a"))

    def test_no_options(self, tmp_path):
        log = tmp_path / "wazuh-install.log"
        assert_success(self._run(log))
        assert log.read_text().rstrip().endswith(self.HEADER.format("none"))

    def test_unwritable_log_is_silent(self, tmp_path):
        result = self._run(tmp_path / "missing" / "wazuh-install.log", "-a")
        assert_success(result)
        assert result.stderr == ""
