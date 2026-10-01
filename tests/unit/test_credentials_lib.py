"""
Unit tests for credentials_lib/wazuh-credentials.sh

Covers: wazuh_password_validate, wazuh_password_generate

The library is POSIX sh and the component packages source it under /bin/sh,
which is dash on Debian-based hosts, so the character-set cases also run under
dash when it is installed.
"""

import os
import shutil
import subprocess

import pytest

from tests.unit.conftest import PROJECT_ROOT, assert_failure, assert_success, run_bash_function

LIB = "credentials_lib/wazuh-credentials.sh"
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,_+:@%^=~-"
CHARSET_MESSAGE = "password must only contain characters from A-Z a-z 0-9 . , _ + : @ % ^ = ~ -"

OUTSIDE_CHARSET = [
    " ", "\t", "\x01", "\r", "\n",
    "*", "?", "!", '"', "'", "\\", "$", "`", "#", "/", "&", ";", "<", ">", "|",
    "(", ")", "[", "]", "{", "}",
    "ñ",        # n with tilde: two bytes in UTF-8
    "\U0001f600",    # an emoji: four bytes in UTF-8
]


def validate(password: str) -> subprocess.CompletedProcess:
    # The value travels through the environment, never through the command line.
    return run_bash_function([LIB], 'wazuh_password_validate "$PW"', env_vars={"PW": password})


def validate_dash(password: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["dash", "-c", f'. "{PROJECT_ROOT / LIB}"; wazuh_password_validate "$PW"'],
        env={**os.environ, "PW": password},
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )


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


@pytest.mark.skipif(shutil.which("dash") is None, reason="dash is not installed")
class TestPasswordValidateUnderDash:
    @pytest.mark.parametrize("character", OUTSIDE_CHARSET, ids=lambda c: f"U+{ord(c):04X}")
    def test_rejects_every_character_outside_the_set(self, character):
        result = validate_dash(f"Abcdefghij1{character}2")
        assert result.returncode != 0
        assert CHARSET_MESSAGE in result.stderr

    def test_rejects_a_value_of_12_bytes_but_7_characters(self):
        # dash measures ${#var} in bytes: the character set, not the length
        # check, has to be what refuses a short non-ASCII value.
        result = validate_dash("ñ" * 5 + "a1")
        assert result.returncode != 0
        assert CHARSET_MESSAGE in result.stderr

    def test_accepts_the_whole_character_set(self):
        assert validate_dash("Aa1.,_+:@%^=~-").returncode == 0


class TestPasswordGenerate:
    def test_generated_passwords_use_only_the_set_and_have_every_class(self):
        script = 'for i in 1 2 3 4 5 6 7 8 9 10; do p=$(wazuh_password_generate) || exit 1; ' \
                 'wazuh_password_validate "$p" || exit 1; printf "%s\\n" "$p"; done'
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
