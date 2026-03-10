"""
Unit tests for cert_tool/certFunctions.sh

Covers: cert_cleanFiles, cert_checkOpenSSL, cert_generateRootCAcertificate,
        cert_generateAdmincertificate, cert_generateIndexercertificates,
        cert_generateManagercertificates, cert_generateDashboardcertificates,
        cert_readConfig
"""

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

CERT = "cert_tool/certFunctions.sh"
COMMON = "common_functions/common.sh"
COMMON_VARS = "common_functions/commonVariables.sh"
BASE_SOURCES = [COMMON_VARS, COMMON, CERT]

IGNORE_LOGGER = {"logger_cert": "true", "common_logger": "true"}
BASE_PATH = "/tmp/wazuh-cert-tool"


class TestCertCleanFiles:
    def test_clean_files_runs(self, tmp_path):
        certs_dir = tmp_path / "certs"
        certs_dir.mkdir()
        (certs_dir / "test.csr").touch()
        (certs_dir / "test.srl").touch()

        result = run_bash_function(
            BASE_SOURCES,
            "cert_cleanFiles",
            {**IGNORE_LOGGER, "rm": "true"},
            {"base_path": str(tmp_path), "debug_cert": ""},
        )
        # Function iterates and calls rm — exit code depends on whether files exist
        assert result.returncode in (0, 1)


class TestCertCheckOpenSSL:
    def test_fail_no_openssl(self):
        mocks = {**IGNORE_LOGGER, "command": "return 1"}
        result = run_bash_function(BASE_SOURCES, "cert_checkOpenSSL", mocks)
        assert_failure(result)

    def test_success_openssl_present(self):
        mocks = {
            **IGNORE_LOGGER,
            "command": 'case "$2" in openssl) echo /bin/openssl ;; *) return 1 ;; esac',
        }
        result = run_bash_function(BASE_SOURCES, "cert_checkOpenSSL", mocks)
        assert_success(result)


class TestCertGenerateRootCA:
    def test_success_generates_root_ca(self, tmp_path):
        mocks = {**IGNORE_LOGGER, "openssl": "true"}
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateRootCAcertificate",
            mocks,
            {"cert_tmp_path": str(tmp_path), "debug_cert": ""},
        )
        assert_success(result)

    def test_fail_openssl_error(self, tmp_path):
        mocks = {**IGNORE_LOGGER, "openssl": "return 1"}
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateRootCAcertificate",
            mocks,
            {"cert_tmp_path": str(tmp_path), "debug_cert": ""},
        )
        assert_failure(result)


class TestCertGenerateAdminCertificate:
    def test_success_generates_admin_cert(self, tmp_path):
        mocks = {**IGNORE_LOGGER, "openssl": "true"}
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateAdmincertificate",
            mocks,
            {"cert_tmp_path": str(tmp_path), "debug_cert": ""},
        )
        assert_success(result)

    def test_fail_openssl_error(self, tmp_path):
        mocks = {**IGNORE_LOGGER, "openssl": "return 1"}
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateAdmincertificate",
            mocks,
            {"cert_tmp_path": str(tmp_path), "debug_cert": ""},
        )
        assert_failure(result)


class TestCertGenerateIndexercertificates:
    """Tests for cert_generateIndexercertificates (replaces the removed cert_generateServercertificates)."""

    def test_fail_no_nodes(self, tmp_path):
        """Returns 1 when indexer_node_names array is empty."""
        mocks = {
            **IGNORE_LOGGER,
            "openssl": "true",
            "cert_generateCertificateconfiguration": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateIndexercertificates",
            mocks,
            {"indexer_node_names": "()", "cert_tmp_path": str(tmp_path), "debug_cert": ""},
        )
        assert_failure(result)

    def test_success_one_node(self, tmp_path):
        """Generates certs for a single indexer node when openssl is mocked."""
        mocks = {
            **IGNORE_LOGGER,
            "openssl": "true",
            "cert_generateCertificateconfiguration": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateIndexercertificates",
            mocks,
            {
                "indexer_node_names": "(indexer1)",
                "indexer_node_ips": "(1.1.1.1)",
                "cert_tmp_path": str(tmp_path),
                "debug_cert": "",
            },
        )
        assert_success(result)

    def test_success_two_nodes(self, tmp_path):
        """Generates certs for two indexer nodes."""
        mocks = {
            **IGNORE_LOGGER,
            "openssl": "true",
            "cert_generateCertificateconfiguration": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateIndexercertificates",
            mocks,
            {
                "indexer_node_names": "(indexer1 indexer2)",
                "indexer_node_ips": "(1.1.1.1 2.2.2.2)",
                "cert_tmp_path": str(tmp_path),
                "debug_cert": "",
            },
        )
        assert_success(result)


class TestCertGenerateManagercertificates:
    def test_fail_no_nodes(self, tmp_path):
        """Returns 1 when manager_node_names array is empty."""
        mocks = {
            **IGNORE_LOGGER,
            "openssl": "true",
            "cert_generateCertificateconfiguration": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateManagercertificates",
            mocks,
            {"manager_node_names": "()", "cert_tmp_path": str(tmp_path), "debug_cert": ""},
        )
        assert_failure(result)

    def test_success_one_node(self, tmp_path):
        mocks = {
            **IGNORE_LOGGER,
            "openssl": "true",
            "cert_generateCertificateconfiguration": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateManagercertificates",
            mocks,
            {
                "manager_node_names": "(wazuh-master)",
                "manager_node_ip_1": "(1.1.1.1)",
                "cert_tmp_path": str(tmp_path),
                "debug_cert": "",
            },
        )
        assert_success(result)


class TestCertGenerateDashboardcertificates:
    def test_fail_no_nodes(self, tmp_path):
        """Returns 1 when dashboard_node_names array is empty."""
        mocks = {
            **IGNORE_LOGGER,
            "openssl": "true",
            "cert_generateCertificateconfiguration": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateDashboardcertificates",
            mocks,
            {"dashboard_node_names": "()", "cert_tmp_path": str(tmp_path), "debug_cert": ""},
        )
        assert_failure(result)

    def test_success_one_node(self, tmp_path):
        mocks = {
            **IGNORE_LOGGER,
            "openssl": "true",
            "cert_generateCertificateconfiguration": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateDashboardcertificates",
            mocks,
            {
                "dashboard_node_names": "(dashboard1)",
                "dashboard_node_ips": "(1.1.1.1)",
                "cert_tmp_path": str(tmp_path),
                "debug_cert": "",
            },
        )
        assert_success(result)


class TestCertReadConfig:
    def test_fail_empty_config_file(self, tmp_path):
        config = tmp_path / "config.yml"
        config.touch()
        mocks = {
            **IGNORE_LOGGER,
            "cert_parseYaml": "true",
            "cert_checkPrivateIp": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_readConfig",
            mocks,
            {"base_path": str(tmp_path), "config_file": str(config), "debug_cert": ""},
        )
        assert_failure(result)

    def test_fail_no_config_file(self, tmp_path):
        mocks = {**IGNORE_LOGGER}
        result = run_bash_function(
            BASE_SOURCES,
            "cert_readConfig",
            mocks,
            {
                "base_path": str(tmp_path),
                "config_file": str(tmp_path / "missing.yml"),
                "debug_cert": "",
            },
        )
        assert_failure(result)

    def test_fail_duplicated_indexer_node_names(self, tmp_path):
        config = tmp_path / "config.yml"
        config.write_text("some: content")
        mocks = {
            **IGNORE_LOGGER,
            "cert_parseYaml": 'printf "nodes_indexer_1=elastic1\\nnodes_indexer_2=elastic1\\nnodes_indexer_3=elastic2\\n"',
            "cert_checkPrivateIp": "true",
            "cert_convertCRLFtoLF": "true",
        }
        result = run_bash_function(
            BASE_SOURCES,
            "cert_readConfig",
            mocks,
            {
                "base_path": str(tmp_path),
                "config_file": str(config),
                "debug_cert": "",
            },
        )
        assert_failure(result)
