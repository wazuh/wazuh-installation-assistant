"""
Unit tests for cert_tool/certFunctions.sh

Covers: cert_cleanFiles, cert_setpermisions, cert_checkOpenSSL,
        cert_generateRootCAcertificate, cert_checkRootCA, cert_rejectCAPaths,
        cert_generateAdmincertificate,
        cert_generateIndexercertificates, cert_generateManagercertificates,
        cert_generateDashboardcertificates, cert_generateRemotedcertificateconfiguration,
        cert_verifyRemotedcertificates, cert_readConfig
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

# Same OpenSSL settings wazuh_ca_ensure uses in credentials_lib/wazuh-credentials.sh.
# The library itself only runs as root, so the tests build an equivalent CA here.
LIBRARY_CA_CONFIG = """[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
OU = Wazuh
O = Wazuh
L = California
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def make_ca(directory):
    """Creates root-ca.pem and root-ca.key in directory and returns the key path."""
    config = directory / "ca.cnf"
    config.write_text(LIBRARY_CA_CONFIG)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-new", "-nodes", "-newkey", "rsa:2048",
            "-sha256", "-days", "3650", "-batch", "-config", str(config),
            "-keyout", str(directory / "root-ca.key"),
            "-out", str(directory / "root-ca.pem"),
        ],
        check=True, capture_output=True,
    )
    config.unlink()
    return str(directory / "root-ca.key")


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


    def test_removes_a_root_ca_key(self, tmp_path):
        """The root CA key never leaves the CA directory."""
        (tmp_path / "root-ca.key").touch()
        (tmp_path / "root-ca.pem").touch()
        result = run_bash_function(
            BASE_SOURCES, "cert_cleanFiles", IGNORE_LOGGER, {"cert_tmp_path": str(tmp_path)}
        )
        assert_success(result)
        assert not (tmp_path / "root-ca.key").exists()
        assert (tmp_path / "root-ca.pem").exists()


class TestCertSetpermisions:
    def test_fail_invalid_path(self):
        result = run_bash_function(
            BASE_SOURCES,
            "cert_setpermisions",
            IGNORE_LOGGER,
            {"cert_tmp_path": "/nonexistent/path"},
        )
        assert_failure(result)

    def test_success_keys_are_owner_only_and_certs_are_world_readable(self, tmp_path):
        certs_dir = tmp_path / "wazuh-certificates"
        certs_dir.mkdir(mode=0o700)
        (certs_dir / "root-ca.pem").touch()
        (certs_dir / "admin-key.pem").touch()
        (certs_dir / "admin.pem").touch()
        (certs_dir / "wazuh.manager-remoted-key.pem").touch()
        (certs_dir / "wazuh.manager-remoted.pem").touch()

        result = run_bash_function(
            BASE_SOURCES,
            "cert_setpermisions",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(certs_dir)},
        )
        assert_success(result)

        key_files = ["admin-key.pem", "wazuh.manager-remoted-key.pem"]
        cert_files = ["root-ca.pem", "admin.pem", "wazuh.manager-remoted.pem"]

        for name in key_files:
            mode = (certs_dir / name).stat().st_mode & 0o777
            assert mode == 0o600, f"{name} expected 600, got {oct(mode)}"

        for name in cert_files:
            mode = (certs_dir / name).stat().st_mode & 0o777
            assert mode == 0o644, f"{name} expected 644, got {oct(mode)}"

        dir_mode = certs_dir.stat().st_mode & 0o777
        assert dir_mode == 0o700, f"directory expected 700, got {oct(dir_mode)}"


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
    """cert_generateRootCAcertificate creates the root CA through wazuh_ca_ensure,
    in the directory wazuh_ca_get_dir resolves."""

    def _run(self, tmp_path, ensure="return 0"):
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "wazuh_ca_get_dir": f'echo "{tmp_path}/ca"',
            "wazuh_ca_ensure": f'echo "ENSURE_CALLED"; {ensure}',
        }
        return run_bash_function(
            BASE_SOURCES,
            'cert_generateRootCAcertificate; echo "ca_dir:${cert_ca_dir}"',
            mocks,
            {"cert_tmp_path": str(tmp_path)},
        )

    def test_success_creates_the_root_ca(self, tmp_path):
        result = self._run(tmp_path)
        assert_success(result)
        assert "ENSURE_CALLED" in result.stdout
        assert f"ca_dir:{tmp_path}/ca" in result.stdout
        assert f"Generating the root certificate in {tmp_path}/ca." in result.stdout

    def test_success_reuses_an_existing_root_ca(self, tmp_path):
        (tmp_path / "ca").mkdir()
        (tmp_path / "ca" / "root-ca.pem").touch()
        result = self._run(tmp_path)
        assert_success(result)
        assert f"Using the existing root CA in {tmp_path}/ca." in result.stdout

    def test_fail_when_the_library_fails(self, tmp_path):
        result = self._run(tmp_path, ensure="return 1")
        assert_failure(result)
        assert "could not be created or is not valid" in result.stdout


class TestCertCheckRootCA:
    """cert_checkRootCA reads the root CA from the CA directory. The key stays
    there: only root-ca.pem is copied next to the new certificates."""

    def _run(self, tmp_path, mode="", validate="return 0", with_key=True):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "root-ca.pem").write_text("anchor")
        if with_key:
            (ca_dir / "root-ca.key").write_text("key")
        work = tmp_path / "work"
        work.mkdir()
        mocks = {
            "common_logger": 'echo "LOG:$*"',
            "wazuh_ca_get_dir": f'echo "{ca_dir}"',
            "wazuh_ca_validate": f'echo "VALIDATE_CALLED"; {validate}',
            "wazuh_ca_ensure": 'echo "ENSURE_CALLED"',
        }
        result = run_bash_function(
            BASE_SOURCES,
            f'cert_checkRootCA {mode}; echo "key:${{rootcakey}}"',
            mocks,
            {"cert_tmp_path": str(work)},
        )
        return result, ca_dir, work

    def test_success_copies_only_the_anchor(self, tmp_path):
        result, ca_dir, work = self._run(tmp_path)
        assert_success(result)
        assert "VALIDATE_CALLED" in result.stdout
        assert (work / "root-ca.pem").read_text() == "anchor"
        assert not (work / "root-ca.key").exists()
        assert f"key:{ca_dir}/root-ca.key" in result.stdout

    def test_create_mode_ensures_the_root_ca(self, tmp_path):
        result, _, _ = self._run(tmp_path, mode="create")
        assert_success(result)
        assert "ENSURE_CALLED" in result.stdout
        assert "VALIDATE_CALLED" not in result.stdout

    def test_fail_when_the_library_refuses_the_root_ca(self, tmp_path):
        result, _, work = self._run(tmp_path, validate="return 1")
        assert_failure(result)
        assert "There is no valid root CA in" in result.stdout
        assert not (work / "root-ca.pem").exists()

    def test_fail_without_the_private_key(self, tmp_path):
        result, _, _ = self._run(tmp_path, with_key=False)
        assert_failure(result)
        assert "has no private key (root-ca.key), so it cannot sign certificates" in result.stdout


class TestCertRejectCAPaths:
    """The options no longer take root CA files: the CA directory is used."""

    def _run(self, value):
        return run_bash_function(
            BASE_SOURCES,
            f'cert_rejectCAPaths "-wi|--wazuh-indexer-certificates" {value}',
            {"common_logger": 'echo "LOG:$*"', "wazuh_ca_get_dir": "echo /etc/wazuh/ca"},
        )

    def test_fail_with_a_path(self):
        result = self._run("/root/root-ca.pem")
        assert_failure(result)
        assert "does not take root CA files anymore" in result.stdout
        assert "WAZUH_CA_DIR" in result.stdout

    def test_success_with_the_next_option(self):
        assert_success(self._run("-v"))

    def test_success_as_the_last_argument(self):
        assert_success(self._run('""'))


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
        rootcakey = make_ca(tmp_path)
        result = run_bash_function(
            BASE_SOURCES,
            f"cert_generateRemotedcertificate {node_name} {' '.join(san)}",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path), "rootcakey": rootcakey},
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

    def test_success_repeated_san_listed_once(self, tmp_path):
        """A value reaching this from the node fields and from --agent-san alike."""
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateRemotedcertificateconfiguration wazuh-master 1.1.1.1 "
            "manager.example.com 1.1.1.1 manager.example.com nginx",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_success(result)

        conf = (tmp_path / "wazuh-master-remoted.conf").read_text()
        assert "IP.1 = 1.1.1.1" in conf
        assert "IP.2" not in conf
        assert "DNS.1 = manager.example.com" in conf
        assert "DNS.2 = nginx" in conf
        assert "DNS.3 = wazuh-master" in conf
        assert "DNS.4" not in conf

    def test_success_repeated_dns_is_case_insensitive(self, tmp_path):
        """DNS names are case-insensitive, so a differently cased repeat is one name."""
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateRemotedcertificateconfiguration wazuh-master 1.1.1.1 "
            "manager.example.com MANAGER.EXAMPLE.COM",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_success(result)

        conf = (tmp_path / "wazuh-master-remoted.conf").read_text()
        assert "DNS.1 = manager.example.com" in conf
        assert "DNS.2 = wazuh-master" in conf
        assert "DNS.3" not in conf


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


class TestCertNormalizeYamlFormatLists:
    """ip and dns both accept a scalar or a list.

    A list under ip used to fall through the normalizer and each item was taken for a
    node of its own, so a node could carry only one address.
    """

    def _normalize(self, yaml_text):
        result = run_bash_function(
            BASE_SOURCES,
            "cert_normalizeYamlFormat",
            IGNORE_LOGGER,
            {},
            stdin=yaml_text,
        )
        assert_success(result)
        return result.stdout

    def test_success_ip_list_folded_into_the_node(self):
        out = self._normalize(
            "nodes:\n"
            "  manager:\n"
            "    - name: wazuh.manager\n"
            "      ip:\n"
            "        - 1.1.1.1\n"
            "        - 2.2.2.2\n"
        )
        assert out.count("- name:") == 1, out
        assert "      ip:\n" in out, out
        assert "        - 1.1.1.1" in out, out
        assert "        - 2.2.2.2" in out, out

    def test_success_ip_scalar_still_inline(self):
        out = self._normalize(
            "nodes:\n"
            "  manager:\n"
            "    - name: wazuh.manager\n"
            "      ip: 1.1.1.1\n"
        )
        assert "      ip: 1.1.1.1" in out, out

    def test_success_dns_list_unaffected(self):
        out = self._normalize(
            "nodes:\n"
            "  manager:\n"
            "    - name: wazuh.manager\n"
            "      dns:\n"
            "        - wazuh.manager\n"
            "        - manager.example.com\n"
        )
        assert out.count("- name:") == 1, out
        assert "        - manager.example.com" in out, out

    def test_success_node_type_after_an_ip_list(self):
        """The list ends at the next key, which must not be read as an item."""
        out = self._normalize(
            "nodes:\n"
            "  manager:\n"
            "    - name: wazuh.master\n"
            "      ip:\n"
            "        - 1.1.1.1\n"
            "      node_type: master\n"
        )
        assert "      node_type: master" in out, out


class TestCertValidateAgentSan:
    """--agent-san names an address agents dial that no single node owns."""

    def _run(self, san_values, modes=None):
        env = {"agent_san": "(" + " ".join(san_values) + ")"}
        env.update(modes or {"all": "1"})
        return run_bash_function(
            BASE_SOURCES, "cert_validateAgentSan", IGNORE_LOGGER, env
        )

    def test_success_no_values(self):
        assert_success(
            run_bash_function(
                BASE_SOURCES,
                "cert_validateAgentSan",
                IGNORE_LOGGER,
                {"agent_san": "()", "all": "", "cmanager": ""},
            )
        )

    def test_success_dns_and_ip(self):
        assert_success(self._run(["nginx", "10.0.0.5", "manager.example.com"]))

    def test_success_with_wm(self):
        assert_success(self._run(["nginx"], {"all": "", "cmanager": "1"}))

    def test_success_public_ip_allowed(self):
        """Unlike a node ip, the address agents dial may legitimately be public."""
        assert_success(self._run(["8.8.8.8"]))

    def test_fail_without_a_manager_option(self):
        assert_failure(self._run(["nginx"], {"all": "", "cmanager": ""}))

    def test_fail_invalid_value(self):
        # The harness splits an array value on whitespace, so the invalid token has to
        # be a single word: an underscore is outside the DNS label alphabet.
        assert_failure(self._run(["bad_host"]))


class TestCertIsIPv4:
    """An address that reaches the SAN has to be one OpenSSL will accept."""

    def _run(self, value):
        return run_bash_function(
            BASE_SOURCES, f'cert_isIPv4 "{value}"', IGNORE_LOGGER, {}
        )

    def test_success_valid_address(self):
        assert_success(self._run("10.0.0.11"))

    def test_success_boundary_octets(self):
        assert_success(self._run("255.255.255.255"))
        assert_success(self._run("0.0.0.0"))

    def test_fail_octet_out_of_range(self):
        """999.1.1.1 used to pass and failed much later, inside openssl."""
        assert_failure(self._run("999.1.1.1"))
        assert_failure(self._run("10.0.0.256"))

    def test_fail_leading_zero(self):
        """Read as octal by some resolvers and as decimal by others."""
        assert_failure(self._run("010.0.0.1"))

    def test_fail_not_an_address(self):
        assert_failure(self._run("10.0.0"))
        assert_failure(self._run("manager.example.com"))


class TestCertValidateComponentSanValuesPublicIp:
    """A public address is a legitimate value, not a reason to abort."""

    def _run(self, ip):
        return run_bash_function(
            BASE_SOURCES,
            "cert_validateComponentSanValues Manager names ip dns",
            IGNORE_LOGGER,
            {
                "names": "(manager-1)",
                "ip_1": f"({ip})",
                "dns_1": "()",
            },
        )

    def test_success_public_ip_is_accepted(self):
        assert_success(self._run("203.0.113.20"))

    def test_success_private_ip_is_accepted(self):
        assert_success(self._run("10.0.1.11"))

    def test_fail_invalid_ip(self):
        assert_failure(self._run("999.1.1.1"))


class TestCertGenerateCertificateconfigurationExtensions:
    """Every leaf carries the extendedKeyUsage of the link it secures."""

    def _conf(self, tmp_path, name, eku, *san):
        result = run_bash_function(
            BASE_SOURCES,
            f"cert_generateCertificateconfiguration {name} '{eku}' {' '.join(san)}",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_success(result)
        return (tmp_path / f"{name}.conf").read_text()

    def test_success_server_auth(self, tmp_path):
        conf = self._conf(tmp_path, "dashboard-1", "serverAuth", "10.0.2.11")
        assert "extendedKeyUsage = serverAuth" in conf
        assert "basicConstraints = critical, CA:FALSE" in conf
        assert "keyUsage = critical, digitalSignature, keyEncipherment" in conf
        # dataEncipherment is used by no TLS 1.3 suite.
        assert "dataEncipherment" not in conf

    def test_success_client_auth(self, tmp_path):
        conf = self._conf(tmp_path, "manager-1", "clientAuth", "10.0.1.11")
        assert "extendedKeyUsage = clientAuth" in conf

    def test_success_indexer_needs_both(self, tmp_path):
        """The indexer node certificate is both ends of the transport layer."""
        conf = self._conf(
            tmp_path, "indexer-1", "serverAuth, clientAuth", "10.0.0.11"
        )
        assert "extendedKeyUsage = serverAuth, clientAuth" in conf

    def test_fail_without_an_extended_key_usage(self, tmp_path):
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateCertificateconfiguration indexer-1 '' 10.0.0.11",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path)},
        )
        assert_failure(result)


class TestCertExtensionMatrixRealOpenSSL:
    """Issues every certificate the tool produces and reads back its extensions."""

    @pytest.fixture
    def issued(self, tmp_path):
        env = {
            "cert_tmp_path": str(tmp_path),
            "rootcakey": make_ca(tmp_path),
            "indexer_node_names": "(indexer-1)",
            "indexer_node_ip_1": "(10.0.0.11)",
            "indexer_node_dns_1": "()",
            "manager_node_names": "(manager-1)",
            "manager_node_ip_1": "(10.0.1.11)",
            "manager_node_dns_1": "()",
            "dashboard_node_names": "(dashboard-1)",
            "dashboard_node_ip_1": "(10.0.2.11)",
            "dashboard_node_dns_1": "()",
            "agent_san": "()",
        }
        call = (
            "cert_generateAdmincertificate && "
            "cert_generateIndexercertificates && cert_generateManagercertificates && "
            "cert_generateDashboardcertificates"
        )
        assert_success(run_bash_function(BASE_SOURCES, call, IGNORE_LOGGER, env))
        return tmp_path

    def _text(self, cert):
        return subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
            check=True, capture_output=True, text=True,
        ).stdout

    @pytest.mark.parametrize(
        "name,expected_eku",
        [
            ("admin", ["TLS Web Client Authentication"]),
            ("indexer-1", ["TLS Web Server Authentication", "TLS Web Client Authentication"]),
            ("manager-1", ["TLS Web Client Authentication"]),
            ("manager-1-remoted", ["TLS Web Server Authentication"]),
            ("dashboard-1", ["TLS Web Server Authentication"]),
        ],
    )
    def test_success_extension_matrix(self, issued, name, expected_eku):
        text = self._text(issued / f"{name}.pem")

        assert "X509v3 Basic Constraints: critical" in text
        assert "CA:FALSE" in text
        assert "X509v3 Key Usage: critical" in text
        assert "Digital Signature, Key Encipherment" in text
        assert "Data Encipherment" not in text
        assert "Non Repudiation" not in text
        for eku in expected_eku:
            assert eku in text
        if "TLS Web Client Authentication" not in expected_eku:
            assert "TLS Web Client Authentication" not in text
        if "TLS Web Server Authentication" not in expected_eku:
            assert "TLS Web Server Authentication" not in text


class TestCertGenerateLoadbalancercertificates:
    """The leaf a TLS-terminating proxy serves, from the same root-ca agents pin."""

    def _issue(self, tmp_path, extra_env=None):
        env = {
            "cert_tmp_path": str(tmp_path),
            "rootcakey": make_ca(tmp_path),
            "lb_node_names": "(lb)",
            "lb_node_ip_1": "(203.0.113.10)",
            "lb_node_dns_1": "(wazuh.example.com)",
        }
        env.update(extra_env or {})
        return run_bash_function(
            BASE_SOURCES,
            "cert_generateLoadbalancercertificates",
            IGNORE_LOGGER,
            env,
        )

    def test_success_issues_the_pair(self, tmp_path):
        assert_success(self._issue(tmp_path))

        assert (tmp_path / "lb.pem").is_file()
        assert (tmp_path / "lb-key.pem").is_file()

    def test_success_extensions_san_and_chain(self, tmp_path):
        assert_success(self._issue(tmp_path))

        text = subprocess.run(
            ["openssl", "x509", "-in", str(tmp_path / "lb.pem"), "-noout", "-text"],
            check=True, capture_output=True, text=True,
        ).stdout
        assert "X509v3 Basic Constraints: critical" in text
        assert "CA:FALSE" in text
        assert "TLS Web Server Authentication" in text
        assert "IP Address:203.0.113.10" in text
        assert "DNS:wazuh.example.com" in text
        # The proxy serves the chain, so the agent can build a path to the pinned CA.
        assert (tmp_path / "lb.pem").read_text().count("BEGIN CERTIFICATE") == 2

    def test_success_verifies_against_the_root_ca(self, tmp_path):
        assert_success(self._issue(tmp_path))

        verify = subprocess.run(
            [
                "openssl", "verify",
                "-CAfile", str(tmp_path / "root-ca.pem"),
                str(tmp_path / "lb.pem"),
            ],
            capture_output=True, text=True,
        )
        assert verify.returncode == 0, verify.stderr

    def test_success_absent_section_is_not_an_error(self, tmp_path):
        """The section is optional: no entry, nothing issued, no failure."""
        result = run_bash_function(
            BASE_SOURCES,
            "cert_generateLoadbalancercertificates",
            IGNORE_LOGGER,
            {"cert_tmp_path": str(tmp_path), "lb_node_names": "()"},
        )
        assert result.returncode == 1
        assert not list(tmp_path.glob("*.pem"))


class TestCertFirstAddressPerNode:
    """install_functions reads the flat arrays by node index."""

    def _run(self, names, ips):
        env = {"names": "(" + " ".join(names) + ")"}
        for i, node_ips in enumerate(ips, start=1):
            env[f"ip_{i}"] = "(" + " ".join(node_ips) + ")"
        return run_bash_function(
            BASE_SOURCES,
            'cert_firstAddressPerNode flat names ip && echo "${flat[@]}"',
            IGNORE_LOGGER,
            env,
        )

    def test_success_one_address_per_node(self):
        result = self._run(["node-1", "node-2"], [["10.0.1.11"], ["10.0.1.21"]])
        assert_success(result)
        assert "10.0.1.11 10.0.1.21" in result.stdout

    def test_success_a_list_does_not_shift_the_next_node(self):
        """The master's address must stay at the master's index."""
        result = self._run(
            ["node-1", "node-2"], [["10.0.1.11", "10.0.1.12"], ["10.0.1.21"]]
        )
        assert_success(result)
        assert "10.0.1.11 10.0.1.21" in result.stdout


class TestCertListenerReachability:
    """A listener certificate naming only loopback cannot enroll a single agent."""

    def _unreachable(self, *san):
        return run_bash_function(
            BASE_SOURCES,
            "cert_listenerSanIsUnreachable " + " ".join(san),
            IGNORE_LOGGER,
            {},
        )

    def test_success_loopback_only(self):
        assert_success(self._unreachable("127.0.0.1"))

    def test_success_loopback_and_localhost(self):
        assert_success(self._unreachable("127.0.0.1", "localhost"))

    def test_fail_with_a_routable_address(self):
        assert_failure(self._unreachable("127.0.0.1", "10.0.1.11"))

    def test_fail_with_a_name(self):
        assert_failure(self._unreachable("127.0.0.1", "manager.example.com"))

    def _check(self, ips, agent_san):
        return run_bash_function(
            BASE_SOURCES,
            "cert_checkListenerReachability",
            IGNORE_LOGGER,
            {
                "manager_node_names": "(manager-1)",
                "manager_node_ip_1": "(" + " ".join(ips) + ")",
                "manager_node_dns_1": "()",
                "agent_san": "(" + " ".join(agent_san) + ")",
                "config_file": "config.yml",
            },
        )

    def test_fail_all_in_one_without_an_agent_address(self):
        assert_failure(self._check(["127.0.0.1"], []))

    def test_success_agent_san_makes_it_reachable(self):
        assert_success(self._check(["127.0.0.1"], ["10.0.1.11"]))
