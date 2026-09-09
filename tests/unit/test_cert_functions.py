"""
Unit tests for cert_tool/certFunctions.sh

Covers: cert_cleanFiles, cert_checkOpenSSL, cert_generateRootCAcertificate,
        cert_generateAdmincertificate, cert_generateIndexercertificates,
        cert_generateManagercertificates, cert_generateDashboardcertificates,
        cert_generateRemotedcertificateconfiguration, cert_verifyRemotedcertificates,
        cert_readConfig
"""

import subprocess
from datetime import datetime, timedelta, timezone

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
                "indexer_node_ip_1": "1.1.1.1",
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
                "indexer_node_ip_1": "1.1.1.1",
                "indexer_node_ip_2": "2.2.2.2",
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
        (tmp_path / "root-ca.pem").write_text("root-ca")
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

    def test_success_issues_remoted_certificate(self, tmp_path):
        """Each manager node also gets the agent listener leaf, CA appended."""
        (tmp_path / "root-ca.pem").write_text("root-ca")
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
        assert (tmp_path / "wazuh-master-remoted.pem").read_text() == "root-ca"


class TestCertGenerateRemotedcertificateRealOpenSSL:
    """Issues a real listener leaf and inspects it, no openssl mock.

    The listener certificate is the only one that goes through "openssl ca", so that
    notBefore can be backdated; these assertions pin what agents end up verifying.
    """

    def _issue(self, tmp_path, node_name, *san):
        subprocess.run(
            [
                "openssl", "req", "-x509", "-new", "-nodes", "-newkey", "rsa:2048",
                "-keyout", str(tmp_path / "root-ca.key"),
                "-out", str(tmp_path / "root-ca.pem"),
                "-batch", "-subj", "/OU=Wazuh/O=Wazuh/L=California/", "-days", "3650",
            ],
            check=True, capture_output=True,
        )
        result = run_bash_function(
            BASE_SOURCES,
            f"cert_generateRemotedcertificate {node_name} {' '.join(san)}",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_success(result)
        return tmp_path / f"{node_name}-remoted.pem"

    def _x509(self, cert, *args):
        return subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", *args],
            check=True, capture_output=True, text=True,
        ).stdout

    def test_success_not_before_is_backdated(self, tmp_path):
        """An agent whose clock lags must not reject a freshly issued certificate."""
        cert = self._issue(tmp_path, "wazuh-master", "1.1.1.1")

        # -checkend counts from now, so -startdate is confirmed through a direct read.
        not_before = self._x509(cert, "-startdate").strip().split("=", 1)[1]
        parsed = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        delta = datetime.now(timezone.utc) - parsed
        assert timedelta(hours=23) < delta < timedelta(hours=25), not_before

    def test_success_extensions_san_and_chain(self, tmp_path):
        cert = self._issue(tmp_path, "wazuh-master", "1.1.1.1", "manager.example.com")

        text = self._x509(cert, "-text")
        assert "CA:FALSE" in text
        assert "TLS Web Server Authentication" in text
        assert "IP Address:1.1.1.1" in text
        assert "DNS:manager.example.com" in text
        assert "DNS:wazuh-master" in text
        assert "C=US, L=California, O=Wazuh, OU=Wazuh, CN=wazuh-master" in self._x509(
            cert, "-subject"
        )
        # remoted serves the file as a chain: the leaf followed by the CA.
        assert cert.read_text().count("BEGIN CERTIFICATE") == 2

    def test_success_verifies_against_the_root_ca(self, tmp_path):
        cert = self._issue(tmp_path, "wazuh-master", "1.1.1.1")

        verify = subprocess.run(
            ["openssl", "verify", "-CAfile", str(tmp_path / "root-ca.pem"), str(cert)],
            capture_output=True, text=True,
        )
        assert verify.returncode == 0, verify.stderr

    def test_success_removes_the_temporary_ca_workspace(self, tmp_path):
        """The workspace would otherwise be packed into the installation tarball."""
        self._issue(tmp_path, "wazuh-master", "1.1.1.1")

        assert not list(tmp_path.glob("*-remoted-ca"))


class TestCertGenerateRemotedcertificateconfiguration:
    def test_fail_no_san(self, tmp_path):
        """Exits when no IP or DNS is given."""
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateRemotedcertificateconfiguration wazuh-master",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_failure(result)

    def test_fail_invalid_san(self, tmp_path):
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateRemotedcertificateconfiguration wazuh-master 'not a host'",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_failure(result)

    def test_success_extensions_and_san(self, tmp_path):
        """Writes the listener extensions and the node's IP and DNS values."""
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateRemotedcertificateconfiguration wazuh-master 1.1.1.1 manager.example.com",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_success(result)

        conf = (tmp_path / "wazuh-master-remoted.conf").read_text()
        assert "CN = wazuh-master" in conf
        assert "basicConstraints = critical,CA:FALSE" in conf
        assert "keyUsage = critical,digitalSignature,keyEncipherment" in conf
        assert "extendedKeyUsage = serverAuth" in conf
        assert "IP.1 = 1.1.1.1" in conf
        assert "DNS.1 = manager.example.com" in conf
        # The node name is a DNS label agents may dial, so it is added too.
        assert "DNS.2 = wazuh-master" in conf

    def test_success_node_name_not_duplicated(self, tmp_path):
        """The node name is not added twice when config.yml already lists it."""
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateRemotedcertificateconfiguration manager.example.com 1.1.1.1 manager.example.com",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_success(result)

        conf = (tmp_path / "manager.example.com-remoted.conf").read_text()
        assert conf.count("manager.example.com") == 2  # CN and DNS.1
        assert "DNS.2" not in conf


class TestCertVerifyRemotedcertificates:
    def test_success_no_manager_nodes(self, tmp_path):
        """Nothing to verify when config.yml has no manager node."""
        result = run_bash_function(
            BASE_SOURCES,
            f"cert_verifyRemotedcertificates {tmp_path}",
            {**IGNORE_LOGGER, "openssl": "false"},
            {"manager_node_names": "()", "cert_tmp_path": str(tmp_path)},
        )
        assert_success(result)

    def test_success_certificate_verifies(self, tmp_path):
        result = run_bash_function(
            BASE_SOURCES,
            f"cert_verifyRemotedcertificates {tmp_path}",
            {**IGNORE_LOGGER, "openssl": "true"},
            {"manager_node_names": "(wazuh-master)", "cert_tmp_path": str(tmp_path)},
        )
        assert_success(result)

    def test_fail_certificate_does_not_verify(self, tmp_path):
        result = run_bash_function(
            BASE_SOURCES,
            f"cert_verifyRemotedcertificates {tmp_path}",
            {**IGNORE_LOGGER, "openssl": "false"},
            {"manager_node_names": "(wazuh-master)", "cert_tmp_path": str(tmp_path)},
        )
        assert_failure(result)


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
                "dashboard_node_ip_1": "1.1.1.1",
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
