"""
Unit tests for install_functions/wazuh-offline-installation.sh

Covers: offline_extractFiles
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

OFFLINE = "install_functions/wazuh-offline-installation.sh"
BASE_SOURCES = [OFFLINE]

IGNORE_LOGGER = {"common_logger": "true"}

RPM_PACKAGES = [
    "wazuh-dashboard-5.0.0-1.x86_64.rpm",
    "wazuh-indexer-5.0.0-1.x86_64.rpm",
    "wazuh-manager-5.0.0-1.x86_64.rpm",
]


class TestOfflineExtractFiles:
    """Tests for offline_extractFiles.

    With ${base_path}/wazuh-offline/ already present the tar step is skipped,
    and the function checks that the Wazuh GPG key and the packages of the
    system type are there.
    """

    def _run(self, tmp_path, packages, key=True):
        packages_path = tmp_path / "wazuh-offline" / "wazuh-packages"
        packages_path.mkdir(parents=True)
        if key:
            (tmp_path / "wazuh-offline" / "GPG-KEY-WAZUH").touch()
        for package in packages:
            (packages_path / package).touch()
        return run_bash_function(
            BASE_SOURCES,
            "offline_extractFiles",
            IGNORE_LOGGER,
            {"sys_type": "yum", "base_path": str(tmp_path)},
        )

    def test_success_all_rpm_packages(self, tmp_path):
        assert_success(self._run(tmp_path, RPM_PACKAGES))

    def test_fail_missing_gpg_key(self, tmp_path):
        assert_failure(self._run(tmp_path, RPM_PACKAGES, key=False))

    @pytest.mark.parametrize("missing", RPM_PACKAGES)
    def test_fail_missing_rpm_package(self, tmp_path, missing):
        packages = [p for p in RPM_PACKAGES if p != missing]
        assert_failure(self._run(tmp_path, packages))


class TestOfflinePrerequisites:
    """Tests for offline_checkPrerequisites and offline_reportMissingPrerequisites.

    The checks collect every missing package, across the assistant round and
    the component round, and the report stops once naming all of them.
    """

    def _run(self, sys_type, installed, rounds):
        if sys_type == "apt-get":
            listing = "\\n".join(f"{p}/noble,now 1.0 amd64 [installed]" for p in installed)
            mocks = {"apt": f'printf "{listing}\\n"'}
        else:
            # rpm -q --whatprovides: gnupg is provided by gnupg2
            provided = " ".join(installed + (["gnupg"] if "gnupg2" in installed else []))
            mocks = {"rpm": f'[[ " {provided} " == *" ${{3}} "* ]]'}
        calls = " && ".join(f"offline_checkPrerequisites {r}" for r in rounds)
        return run_bash_function(
            BASE_SOURCES + ["install_functions/installVariables.sh"],
            f"{calls} && offline_reportMissingPrerequisites",
            {"common_logger": 'echo "$@"', **mocks},
            {"sys_type": sys_type},
        )

    def test_all_installed(self):
        installed = ["curl", "tar", "gnupg", "openssl", "tar", "libcap2-bin", "diffutils"]
        assert_success(self._run(
            "apt-get", installed,
            ["wia_offline_dependencies curl tar gnupg openssl", "dashboard"],
        ))

    def test_apt_lists_missing_from_both_rounds_once(self):
        # gnupg misses in the assistant round, libcap2-bin in the component
        # round, and openssl, missing too, is in both lists but is named once
        installed = ["curl", "tar", "diffutils"]
        result = self._run(
            "apt-get", installed,
            ["wia_offline_dependencies curl tar gnupg openssl", "dashboard"],
        )
        assert_failure(result)
        assert "not installed: gnupg openssl libcap2-bin." in result.stdout
        assert "apt-get download gnupg openssl libcap2-bin" in result.stdout

    def test_yum_suggests_yumdownloader(self):
        # gnupg2 installed counts as gnupg
        installed = ["curl", "tar", "gnupg2", "openssl", "diffutils", "util-linux"]
        result = self._run(
            "yum", installed,
            ["wia_offline_dependencies curl tar gnupg openssl", "dashboard"],
        )
        assert_failure(result)
        assert "not installed: libcap." in result.stdout
        assert "yumdownloader --resolve libcap" in result.stdout
