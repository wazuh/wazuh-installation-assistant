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
    "wazuh-dashboard-5.1.0-1.x86_64.rpm",
    "wazuh-indexer-5.1.0-1.x86_64.rpm",
    "wazuh-manager-5.1.0-1.x86_64.rpm",
]


class TestOfflineExtractFiles:
    """Tests for offline_extractFiles.

    With ${base_path}/wazuh-offline/ already present the tar step is skipped,
    and the function checks that the packages of the system type are there.
    """

    def _run(self, tmp_path, packages):
        packages_path = tmp_path / "wazuh-offline" / "wazuh-packages"
        packages_path.mkdir(parents=True)
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

    @pytest.mark.parametrize("missing", RPM_PACKAGES)
    def test_fail_missing_rpm_package(self, tmp_path, missing):
        packages = [p for p in RPM_PACKAGES if p != missing]
        assert_failure(self._run(tmp_path, packages))
