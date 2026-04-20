"""
Unit tests for common_functions/common.sh

Covers: common_checkSystem, common_checkInstalled
"""

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON]
IGNORE_LOGGER = {"common_logger": "true"}


class TestCommonCheckSystem:
    def _run(self, yum_present: bool, apt_present: bool):
        mocks = {
            **IGNORE_LOGGER,
            "command": (
                f'case "$2" in '
                f'yum) {"echo /usr/bin/yum" if yum_present else "return 1"} ;; '
                f'apt-get) {"echo /usr/bin/apt-get" if apt_present else "return 1"} ;; '
                f'*) return 1 ;; esac'
            ),
        }
        return run_bash_function(BASE_SOURCES, "common_checkSystem", mocks)

    def test_fail_no_package_manager(self):
        assert_failure(self._run(False, False))

    def test_success_yum_present(self):
        result = self._run(True, False)
        assert_success(result)
        assert "yum" in result.stdout or result.returncode == 0

    def test_success_apt_present(self):
        result = self._run(False, True)
        assert_success(result)


class TestCommonCheckInstalled:
    def _run(self, env_vars=None, extra_mocks=None):
        mocks = {**IGNORE_LOGGER, **(extra_mocks or {})}
        return run_bash_function(BASE_SOURCES, "common_checkInstalled", mocks, env_vars)

    def test_success_nothing_installed(self):
        mocks = {
            **IGNORE_LOGGER,
            "yum": "return 1",
            "dpkg-query": "return 1",
            "rpm": "return 1",
        }
        result = self._run(env_vars={"sys_type": "yum"}, extra_mocks=mocks)
        assert_success(result)

    def test_success_wazuh_manager_installed_yum(self):
        mocks = {
            **IGNORE_LOGGER,
            "yum": "echo wazuh-manager.x86_64",
            "grep": "echo wazuh-manager.x86_64 5.0.1-1",
        }
        result = self._run(env_vars={"sys_type": "yum"}, extra_mocks=mocks)
        assert_success(result)
