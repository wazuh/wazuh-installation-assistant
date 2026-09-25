"""
Unit tests for the password policy shared by credentials_lib/wazuh-credentials.sh
and wazuh-passwords-tool (passwords_tool/passwordsFunctions.sh)

Covers: wazuh_password_validate and passwords_checkPassword against one corpus,
        wazuh_password_generate and passwords_generatePassword, and each
        generator's output against the other tool's validator

The two scripts implement the policy separately, because each has to work on
its own once downloaded. These tests are what keeps them aligned: 12 to 64
characters, only A-Z a-z 0-9 . , _ + : @ % ^ = ~ -, and at least one uppercase
letter, one lowercase letter, one digit and one symbol.
"""

import pytest

from tests.unit.conftest import run_bash_function
from tests.unit.test_credentials_lib import CHARSET, OUTSIDE_CHARSET

LIB = ["credentials_lib/wazuh-credentials.sh"]
TOOL = [
    "common_functions/commonVariables.sh",
    "common_functions/common.sh",
    "passwords_tool/passwordsFunctions.sh",
]
TOOL_MOCKS = {"common_logger": "true", "installCommon_rollBack": "true"}
SYMBOLS = ".,_+:@%^=~-"

VALIDATORS = {
    "credentials-lib": (LIB, 'wazuh_password_validate "$PW"', {}),
    "passwords-tool": (TOOL, 'passwords_checkPassword "$PW"', TOOL_MOCKS),
}

ACCEPTED = (
    ["Abcdefghij1.", "Aa1." + "b" * 60, "Aa1.,_+:@%^=~-"]
    + [f"Abcdefghij1{symbol}" for symbol in SYMBOLS]
)
REJECTED = (
    [
        "Abcdefghi1.",          # 11 characters
        "Aa1." + "b" * 61,      # 65 characters
        "ABCDEFGHIJ1.",         # no lowercase letter
        "abcdefghij1.",         # no uppercase letter
        "Abcdefghijk.",         # no digit
        "Abcdefghij12",         # no symbol
    ]
    # Every class present: the only violation is the character outside the set.
    + [f"Abcdefghij1.{character}" for character in OUTSIDE_CHARSET]
)


def validate(implementation: str, password: str) -> int:
    sources, call, mocks = VALIDATORS[implementation]
    return run_bash_function(sources, call, mocks, {"PW": password}).returncode


def generate(implementation: str, count: int) -> list[str]:
    if implementation == "credentials-lib":
        sources, body, mocks = LIB, 'p=$(wazuh_password_generate) || exit 1; printf "%s\\n" "$p"', {}
    else:
        sources, body, mocks = TOOL, 'passwords_generatePassword; printf "%s\\n" "$password"', TOOL_MOCKS
    result = run_bash_function(sources, f"for i in $(seq 1 {count}); do {body}; done", mocks)
    assert result.returncode == 0, result.stderr
    return result.stdout.split()


@pytest.mark.parametrize("implementation", VALIDATORS)
class TestSameVerdict:
    @pytest.mark.parametrize("password", ACCEPTED)
    def test_accepts(self, implementation, password):
        assert validate(implementation, password) == 0

    @pytest.mark.parametrize("password", REJECTED, ids=lambda p: p.encode("unicode_escape").decode())
    def test_rejects(self, implementation, password):
        assert validate(implementation, password) != 0


@pytest.mark.parametrize("implementation", VALIDATORS)
class TestSameGeneration:
    def test_generates_32_characters_from_the_set_with_every_class(self, implementation):
        passwords = generate(implementation, 10)
        assert len(passwords) == 10
        for password in passwords:
            assert len(password) == 32
            assert set(password) <= set(CHARSET)
            assert any(c.islower() for c in password)
            assert any(c.isupper() for c in password)
            assert any(c.isdigit() for c in password)
            assert any(c in SYMBOLS for c in password)


@pytest.mark.parametrize("generator,validator", [
    ("credentials-lib", "passwords-tool"),
    ("passwords-tool", "credentials-lib"),
])
def test_each_tool_accepts_what_the_other_generates(generator, validator):
    for password in generate(generator, 10):
        assert validate(validator, password) == 0, f"{validator} rejected a password from {generator}"
