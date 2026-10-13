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


def _awk(source: str, name: str, tmp_path, value: str = "", action: str = "set") -> str:
    """Run the awk program of wazuh_env_set/unset (the real one, extracted) over `source`."""
    import re

    script = (PROJECT_ROOT / "credentials_lib/wazuh-credentials.sh").read_text()
    program = re.search(r"-v value_file=\"\$_wazuh_value_file\" '(.*?)\n    ' \"\$_wazuh_source\"", script, re.S).group(1)
    value_file = tmp_path / "value"
    value_file.write_text(value + "\n")
    src = tmp_path / "src"
    src.write_text(source)
    result = subprocess.run(
        ["awk", "-v", f"action={action}", "-v", f"wanted={name}", "-v", f"value_file={value_file}", program, str(src)],
        capture_output=True, text=True, check=True,
    )
    return result.stdout


KEYS = [
    "WAZUH_INDEXER_ADMIN_PASSWORD",
    "WAZUH_INDEXER_KIBANASERVER_PASSWORD",
    "WAZUH_INDEXER_MANAGER_PASSWORD",
    "WAZUH_MANAGER_API_PASSWORD",
    "WAZUH_MANAGER_WUI_PASSWORD",
]
ADMIN = KEYS[0]
BEGIN = "# >>> wazuh generated — do not edit <<<"
END = "# >>> end wazuh generated <<<"
HEADER = [
    "# Written by the Wazuh packages and tools. Editing a value here changes nothing.",
    "# To change a password: wazuh-passwords-tool.sh -u <user>",
    "# A host only holds the keys of the components installed on it.",
    "#",
    "#                 User                   Key                                  Used for",
    "# Logins:",
    "#                 admin                  WAZUH_INDEXER_ADMIN_PASSWORD         Wazuh dashboard (web UI) and Wazuh indexer API",
    "#                 wazuh                  WAZUH_MANAGER_API_PASSWORD           Wazuh server API (curl, scripts)",
    "# Service accounts the components connect with, not logins:",
    "#                 kibanaserver           WAZUH_INDEXER_KIBANASERVER_PASSWORD  dashboard to indexer",
    "#                 wazuh-manager          WAZUH_INDEXER_MANAGER_PASSWORD       manager to indexer",
    "#                 wazuh-internal-client  WAZUH_MANAGER_WUI_PASSWORD           dashboard to server API",
    "#",
]


def _install(tmp_path, value="Aa1.install-pass"):
    out = ""
    for key in KEYS:
        out = _awk(out, key, tmp_path, value)
    return out


def _expected(values):
    return [BEGIN, *HEADER, *(f"{k}={v}" for k, v in values.items()), END]


class TestCredentialsEnvWriter:
    def test_password_alphabet_is_written_bare(self, tmp_path):
        out = _awk("", ADMIN, tmp_path, "Aa0.,_+:@%^=~-xyz")
        assert f"{ADMIN}=Aa0.,_+:@%^=~-xyz\n" in out

    def test_values_outside_the_alphabet_are_still_escaped(self, tmp_path):
        out = _awk("", "OTHER", tmp_path, 'a b$c"d')
        assert 'OTHER="a b\\$c\\"d"\n' in out

    def test_install_writes_the_header_then_the_bare_keys(self, tmp_path):
        assert _install(tmp_path).splitlines() == _expected({k: "Aa1.install-pass" for k in KEYS})

    def test_rotating_keeps_one_header(self, tmp_path):
        out = _install(tmp_path)
        for _ in range(2):
            for key in KEYS:
                out = _awk(out, key, tmp_path, "Bb2.rotated-pass")
        assert out.splitlines() == _expected({k: "Bb2.rotated-pass" for k in KEYS})

    def test_unset_leaves_the_header_and_reinstalling_does_not_repeat_it(self, tmp_path):
        out = _awk(_install(tmp_path), ADMIN, tmp_path, action="unset")
        assert out.splitlines() == _expected({k: "Aa1.install-pass" for k in KEYS[1:]})
        out = _awk(out, ADMIN, tmp_path, "Cc3.reinstalled")
        assert out.splitlines() == _expected({**{k: "Aa1.install-pass" for k in KEYS[1:]}, ADMIN: "Cc3.reinstalled"})

    def test_the_header_of_a_file_written_before_is_replaced(self, tmp_path):
        old = (
            f"{BEGIN}\n# Editing a value here does not change the deployment.\n# To rotate, use wazuh-passwords-tool.sh.\n"
            f"# admin: login of the Wazuh dashboard and administrator of the indexer\n{ADMIN}=\"Dd4.old-quoted\"\n{END}\n"
        )
        out = _awk(old, "WAZUH_MANAGER_API_PASSWORD", tmp_path, "Ee5.api-pass")
        assert out.splitlines() == _expected({ADMIN: '"Dd4.old-quoted"', "WAZUH_MANAGER_API_PASSWORD": "Ee5.api-pass"})

    def test_the_header_with_the_wazuh_wui_user_is_replaced(self, tmp_path):
        old_table = [
            "#                 User           Key                                  Used for",
            "# Logins:",
            "#                 admin          WAZUH_INDEXER_ADMIN_PASSWORD         Wazuh dashboard (web UI) and Wazuh indexer API",
            "#                 wazuh          WAZUH_MANAGER_API_PASSWORD           Wazuh server API (curl, scripts)",
            "# Service accounts the components connect with, not logins:",
            "#                 kibanaserver   WAZUH_INDEXER_KIBANASERVER_PASSWORD  dashboard to indexer",
            "#                 wazuh-manager  WAZUH_INDEXER_MANAGER_PASSWORD       manager to indexer",
            "#                 wazuh-wui      WAZUH_MANAGER_WUI_PASSWORD           dashboard to server API",
            "#",
        ]
        old = "\n".join([BEGIN, *HEADER[:4], *old_table, f"{ADMIN}=Gg7.old-pass", END]) + "\n"
        out = _awk(old, "WAZUH_MANAGER_WUI_PASSWORD", tmp_path, "Hh8.wui-pass")
        assert out.splitlines() == _expected({ADMIN: "Gg7.old-pass", "WAZUH_MANAGER_WUI_PASSWORD": "Hh8.wui-pass"})

    def test_lines_outside_the_block_are_kept(self, tmp_path):
        out = _awk("# operator note\nCUSTOM=1\n", ADMIN, tmp_path, "Ff6.password-x")
        assert out.splitlines()[:2] == ["# operator note", "CUSTOM=1"]
