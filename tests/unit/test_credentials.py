"""
Unit tests for common_functions/credentials.sh

Covers: common_passwordValidate, common_passwordGenerate, common_envGet,
common_envSet, common_caGetDir, common_caValidate, common_caEnsure
"""

import subprocess

import pytest

from tests.unit.conftest import assert_failure, assert_success, run_bash_function

LIB = "common_functions/credentials.sh"
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,_+:@%^=~-"
CHARSET_MESSAGE = "password must only contain characters from A-Z a-z 0-9 . , _ + : @ % ^ = ~ -"

OUTSIDE_CHARSET = [
    " ", "\t", "\x01", "\r", "\n",
    "*", "?", "!", '"', "'", "\\", "$", "`", "#", "/", "&", ";", "<", ">", "|",
    "(", ")", "[", "]", "{", "}",
    "ñ",        # n with tilde: two bytes in UTF-8
    "\U0001f600",    # an emoji: four bytes in UTF-8
]

# The tests do not run as root: the owner checks and changes are mocked.
ROOT_MOCKS = {"chown": "true", "stat": "echo 0"}


def validate(password: str) -> subprocess.CompletedProcess:
    # The value travels through the environment, never through the command line.
    return run_bash_function([LIB], 'common_passwordValidate "$PW"', env_vars={"PW": password})


class TestPasswordValidate:
    def test_accepts_the_whole_character_set(self):
        assert_success(validate("Aa1.,_+:@%^=~-"))

    @pytest.mark.parametrize("length", [12, 64])
    def test_accepts_the_length_boundaries(self, length):
        assert_success(validate("Aa1." + "b" * (length - 4)))

    @pytest.mark.parametrize("length", [11, 65])
    def test_rejects_lengths_outside_12_to_64(self, length):
        result = validate("Aa1." + "b" * (length - 4))
        assert_failure(result)
        assert "between 12 and 64 characters" in result.stderr

    @pytest.mark.parametrize("password,missing", [
        ("ABCDEFGHIJ1.", "lowercase letter"),
        ("abcdefghij1.", "uppercase letter"),
        ("Abcdefghijk.", "digit"),
        ("Abcdefghij12", "symbol from . , _ + : @ % ^ = ~ -"),
    ])
    def test_rejects_a_password_missing_one_class(self, password, missing):
        result = validate(password)
        assert_failure(result)
        assert f"at least one {missing}" in result.stderr

    @pytest.mark.parametrize("symbol", list(".,_+:@%^=~-"))
    def test_accepts_each_symbol_on_its_own(self, symbol):
        assert_success(validate(f"Abcdefghij1{symbol}"))

    @pytest.mark.parametrize("character", OUTSIDE_CHARSET, ids=lambda c: f"U+{ord(c):04X}")
    def test_rejects_every_character_outside_the_set(self, character):
        result = validate(f"Abcdefghij1{character}2")
        assert_failure(result)
        assert CHARSET_MESSAGE in result.stderr

    def test_never_prints_the_rejected_value(self):
        password = "Canary-Leak-123*"
        result = validate(password)
        assert_failure(result)
        assert password not in result.stdout
        assert password not in result.stderr


class TestPasswordGenerate:
    def test_generated_passwords_use_only_the_set_and_have_every_class(self):
        script = 'for i in 1 2 3 4 5 6 7 8 9 10; do p=$(common_passwordGenerate) || exit 1; ' \
                 'common_passwordValidate "$p" || exit 1; printf "%s\\n" "$p"; done'
        result = run_bash_function([LIB], script)
        assert_success(result)
        passwords = result.stdout.split()
        assert len(passwords) == 10
        for password in passwords:
            assert len(password) == 32
            assert set(password) <= set(CHARSET)
            assert any(c.islower() for c in password)
            assert any(c.isupper() for c in password)
            assert any(c.isdigit() for c in password)
            assert any(c in ".,_+:@%^=~-" for c in password)
        assert len(set(passwords)) == 10



class TestEnvGet:
    def test_reads_plain_and_quoted_values(self, tmp_path):
        env = tmp_path / "local.env"
        env.write_text('A_KEY=Plain1.value\nB_KEY="Quoted1.value"\nC_KEY=\'Single1.value\'\n')
        for key, value in (("A_KEY", "Plain1.value"), ("B_KEY", "Quoted1.value"), ("C_KEY", "Single1.value")):
            result = run_bash_function([LIB], f'common_envGet "{env}" {key}', mock_funcs=ROOT_MOCKS)
            assert_success(result)
            assert result.stdout == f"{value}\n"

    def test_the_last_value_wins(self, tmp_path):
        env = tmp_path / "local.env"
        env.write_text("A_KEY=first\nA_KEY=second\n")
        result = run_bash_function([LIB], f'common_envGet "{env}" A_KEY', mock_funcs=ROOT_MOCKS)
        assert result.stdout == "second\n"

    def test_returns_1_for_a_missing_key_or_file(self, tmp_path):
        env = tmp_path / "local.env"
        env.write_text("A_KEY=value\n")
        result = run_bash_function([LIB], f'common_envGet "{env}" B_KEY; echo "rc=$?"', mock_funcs=ROOT_MOCKS)
        assert "rc=1" in result.stdout
        result = run_bash_function([LIB], f'common_envGet "{tmp_path}/none.env" B_KEY; echo "rc=$?"', mock_funcs=ROOT_MOCKS)
        assert "rc=1" in result.stdout

    def test_returns_2_for_a_file_not_owned_by_root(self, tmp_path):
        env = tmp_path / "local.env"
        env.write_text("A_KEY=value\n")
        result = run_bash_function([LIB], f'common_envGet "{env}" A_KEY; echo "rc=$?"', mock_funcs={"stat": "echo 1000"})
        assert "rc=2" in result.stdout
        assert "value" not in result.stdout.replace("rc=2", "")

    def test_returns_2_for_a_link(self, tmp_path):
        target = tmp_path / "target.env"
        target.write_text("A_KEY=value\n")
        (tmp_path / "local.env").symlink_to(target)
        result = run_bash_function([LIB], f'common_envGet "{tmp_path}/local.env" A_KEY; echo "rc=$?"', mock_funcs=ROOT_MOCKS)
        assert "rc=2" in result.stdout


class TestEnvSet:
    def test_creates_the_file_with_mode_600(self, tmp_path):
        env = tmp_path / "local.env"
        result = run_bash_function([LIB], f'common_envSet "{env}" A_KEY "Aa1.value-one"', mock_funcs=ROOT_MOCKS)
        assert_success(result)
        assert env.read_text() == "A_KEY=Aa1.value-one\n"
        assert oct(env.stat().st_mode & 0o777) == "0o600"

    def test_replaces_a_key_in_its_line_and_keeps_the_others(self, tmp_path):
        env = tmp_path / "local.env"
        env.write_text("A_KEY=old\nB_KEY=other\nC_KEY=last\n")
        result = run_bash_function([LIB], f'common_envSet "{env}" B_KEY "New.Value-1=x"', mock_funcs=ROOT_MOCKS)
        assert_success(result)
        assert env.read_text() == "A_KEY=old\nB_KEY=New.Value-1=x\nC_KEY=last\n"

    def test_adds_a_new_key_at_the_end(self, tmp_path):
        env = tmp_path / "local.env"
        env.write_text("A_KEY=old\n")
        result = run_bash_function([LIB], f'common_envSet "{env}" B_KEY new', mock_funcs=ROOT_MOCKS)
        assert_success(result)
        assert env.read_text() == "A_KEY=old\nB_KEY=new\n"

    def test_refuses_a_link(self, tmp_path):
        target = tmp_path / "target.env"
        target.write_text("")
        (tmp_path / "local.env").symlink_to(target)
        result = run_bash_function([LIB], f'common_envSet "{tmp_path}/local.env" A_KEY value', mock_funcs=ROOT_MOCKS)
        assert_failure(result)
        assert target.read_text() == ""

    def test_leaves_no_temporary_file(self, tmp_path):
        env = tmp_path / "local.env"
        run_bash_function([LIB], f'common_envSet "{env}" A_KEY value', mock_funcs=ROOT_MOCKS)
        assert [p.name for p in tmp_path.iterdir()] == ["local.env"]


class TestCaGetDir:
    def test_default_is_wazuh_ca_next_to_the_tool(self):
        result = run_bash_function([LIB], "common_caGetDir", env_vars={"base_path": "/opt/tools", "WAZUH_CA_DIR": ""})
        assert result.stdout == "/opt/tools/wazuh-ca\n"

    def test_wazuh_ca_dir_overrides_it(self):
        result = run_bash_function([LIB], "common_caGetDir", env_vars={"base_path": "/opt/tools", "WAZUH_CA_DIR": "/srv/ca"})
        assert result.stdout == "/srv/ca\n"

    def test_refuses_a_relative_path(self):
        result = run_bash_function([LIB], "common_caGetDir", env_vars={"WAZUH_CA_DIR": "ca"})
        assert_failure(result)


class TestCaEnsureAndValidate:
    def test_creates_a_ca_and_validates_it(self, tmp_path):
        ca = tmp_path / "ca"
        result = run_bash_function([LIB], f'common_caEnsure "{ca}" && common_caValidate "{ca}"', mock_funcs=ROOT_MOCKS)
        assert_success(result)
        assert oct(ca.stat().st_mode & 0o777) == "0o700"
        assert oct((ca / "root-ca.key").stat().st_mode & 0o777) == "0o400"
        assert oct((ca / "root-ca.pem").stat().st_mode & 0o777) == "0o644"
        text = subprocess.run(["openssl", "x509", "-in", str(ca / "root-ca.pem"), "-noout", "-text"],
                              capture_output=True, text=True).stdout
        assert "CA:TRUE" in text
        assert "Certificate Sign" in text

    def test_never_replaces_an_existing_ca(self, tmp_path):
        ca = tmp_path / "ca"
        run_bash_function([LIB], f'common_caEnsure "{ca}"', mock_funcs=ROOT_MOCKS)
        before = (ca / "root-ca.pem").read_bytes()
        result = run_bash_function([LIB], f'common_caEnsure "{ca}"', mock_funcs=ROOT_MOCKS)
        assert_success(result)
        assert (ca / "root-ca.pem").read_bytes() == before

    def test_a_certificate_without_its_key_is_valid(self, tmp_path):
        ca = tmp_path / "ca"
        run_bash_function([LIB], f'common_caEnsure "{ca}"', mock_funcs=ROOT_MOCKS)
        (ca / "root-ca.key").chmod(0o600)
        (ca / "root-ca.key").unlink()
        assert_success(run_bash_function([LIB], f'common_caValidate "{ca}"'))

    def test_a_key_without_its_certificate_fails(self, tmp_path):
        ca = tmp_path / "ca"
        run_bash_function([LIB], f'common_caEnsure "{ca}"', mock_funcs=ROOT_MOCKS)
        (ca / "root-ca.pem").chmod(0o600)
        (ca / "root-ca.pem").unlink()
        result = run_bash_function([LIB], f'common_caEnsure "{ca}"', mock_funcs=ROOT_MOCKS)
        assert_failure(result)
        assert "without root-ca.pem" in result.stderr

    def test_a_key_of_another_ca_fails(self, tmp_path):
        first, second = tmp_path / "first", tmp_path / "second"
        run_bash_function([LIB], f'common_caEnsure "{first}"; common_caEnsure "{second}"', mock_funcs=ROOT_MOCKS)
        (first / "root-ca.key").chmod(0o600)
        (first / "root-ca.key").write_bytes((second / "root-ca.key").read_bytes())
        result = run_bash_function([LIB], f'common_caValidate "{first}"')
        assert_failure(result)
        assert "does not match" in result.stderr
