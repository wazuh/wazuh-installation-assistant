from unittest.mock import patch

import pytest

from installation_assistant.checks.global_checks import check_if_sudo


def test_check_if_sudo_with_superuser_privileges():
    """
    Test check_if_sudo when the module is run with superuser privileges.
    """
    with patch("os.geteuid", return_value=0):
        assert check_if_sudo() is None


def test_check_if_sudo_without_superuser_privileges():
    """
    Test check_if_sudo when the module is not run with superuser privileges.
    """
    with (
        patch("os.geteuid", return_value=1000),
        pytest.raises(PermissionError, match="The installation assistant module must be run with superuser privileges"),
    ):
        check_if_sudo()
