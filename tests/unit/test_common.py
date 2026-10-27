"""
Unit tests for common_functions/common.sh

Covers: common_checkSystem, common_checkInstalled, common_isDebInstalled, common_curl, common_logger
"""

import os

import pytest

from tests.unit.conftest import VERBOSE_DEBUG, assert_failure, assert_success, run_bash_function

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
            "grep": "echo wazuh-manager.x86_64 5.0.0",
        }
        result = self._run(env_vars={"sys_type": "yum"}, extra_mocks=mocks)
        assert_success(result)

    def test_success_all_installed_apt(self):
        result = run_bash_function(
            BASE_SOURCES,
            'common_checkInstalled; echo "${wazuh_installed}${indexer_installed}${dashboard_installed}"',
            {**IGNORE_LOGGER, "dpkg-query": "echo installed"},
            {"sys_type": "apt-get"},
        )
        assert_success(result)
        assert result.stdout.strip() == "111"

    def test_logs_the_check_at_debug_level(self):
        result = run_bash_function(
            BASE_SOURCES,
            "common_checkInstalled",
            {"common_logger": 'echo "$@"', "dpkg-query": "return 1"},
            {"sys_type": "apt-get"},
        )
        assert_success(result)
        assert "-d Checking Wazuh installation." in result.stdout.splitlines()


class TestCommonIsDebInstalled:
    """apt list --installed also lists the packages whose configuration failed."""

    @pytest.mark.parametrize(
        "status, installed",
        [
            ("installed", True),
            ("half-configured", True),
            ("unpacked", True),
            ("config-files", False),
            ("not-installed", False),
            ("", False),
        ],
    )
    def test_status(self, status, installed):
        result = run_bash_function(
            BASE_SOURCES,
            "common_isDebInstalled wazuh-manager",
            {**IGNORE_LOGGER, "dpkg-query": f'echo -n "{status}"'},
        )
        assert (result.returncode == 0) == installed


class TestCommonCurl:
    """common_curl returns the exit code of curl, also when debug sends the
    output through tee (-v)."""

    @pytest.mark.parametrize("debug", ["", VERBOSE_DEBUG])
    @pytest.mark.parametrize("connrefused", ["", "1"])
    def test_returns_the_curl_error(self, debug, connrefused):
        result = run_bash_function(
            BASE_SOURCES,
            'common_curl -sS https://localhost --fail ${debug}',
            {**IGNORE_LOGGER, "curl": "return 22"},
            {"debug": debug, "curl_has_connrefused": connrefused},
        )
        assert result.returncode == 22

    @pytest.mark.parametrize("debug", ["", VERBOSE_DEBUG])
    def test_retries_when_the_connection_is_refused(self, tmp_path, debug):
        calls = tmp_path / "calls"
        result = run_bash_function(
            BASE_SOURCES,
            'common_curl -sS https://localhost --fail ${debug}',
            {
                **IGNORE_LOGGER,
                "sleep": "true",
                "curl": f'echo call >> {calls}; [ "$(wc -l < {calls})" -ge 2 ] && return 0; return 7',
            },
            {"debug": debug, "curl_has_connrefused": ""},
        )
        assert_success(result)
        assert calls.read_text().count("call") == 2


@pytest.mark.skipif(os.geteuid() == 0, reason="needs a regular user")
class TestCommonLoggerAsRegularUser:
    """A regular user only writes the log from the certs tool. The installer
    does not set cert_tool_script_name, which used to match any script."""

    def _run(self, tmp_path, script_name):
        logfile = tmp_path / "wazuh-install.log"
        result = run_bash_function(
            BASE_SOURCES,
            'common_logger "message"',
            env_vars={"logfile": str(logfile), "cert_tool_script_name": script_name},
        )
        assert_success(result)
        assert "message" in result.stdout
        return logfile

    def test_installer_does_not_write_the_log(self, tmp_path):
        assert not self._run(tmp_path, "").exists()

    def test_certs_tool_writes_the_log(self, tmp_path):
        # The test runs the function from bash, so $0 is bash.
        assert "message" in self._run(tmp_path, "bash").read_text()
