from unittest.mock import patch

import pytest

from installation_assistant.checks.packages_installation_checks import (
    SystemNotSupportedError,
    check_architecture,
    check_distribution,
    check_package_manager,
)
from installation_assistant.utils import ComponentArch
from installation_assistant.utils.enums import PackageManager


@pytest.fixture
def mock_logger():
    with patch("installation_assistant.checks.packages_installation_checks.logger") as mock_logger:
        yield mock_logger


def test_system_not_supported_error_message():
    message = "Test unsupported system."
    expected_message = (
        f"{message} Please checks the permitted operating systems in the documentation: "
        "https://documentation.wazuh.com/current/quickstart.html#operating-system"
    )

    with pytest.raises(SystemNotSupportedError) as exc_info:
        raise SystemNotSupportedError(message)

    assert str(exc_info.value) == expected_message


@pytest.mark.parametrize(
    "mock_arch, expected_arch",
    [
        ("x86_64", ComponentArch.X86_64),
        ("amd64", ComponentArch.AMD64),
        ("aarch64", ComponentArch.AARCH64),
        ("arm64", ComponentArch.ARM64),
    ],
)
def test_check_architecture_supported(mock_arch, expected_arch):
    with patch("platform.machine", return_value=mock_arch):
        assert check_architecture() == expected_arch


@pytest.mark.parametrize(
    "mock_arch",
    ["i386", "powerpc", "sparc", "unknown_arch"],
)
def test_check_architecture_unsupported(mock_arch):
    with patch("platform.machine", return_value=mock_arch):
        with pytest.raises(SystemNotSupportedError) as exc_info:
            check_architecture()

        assert str(exc_info.value) == (
            f"Unsupported architecture: {mock_arch}. Only x86_64/AMD64 or AARCH64/ARM64 are supported. "
            "Please checks the permitted operating systems in the documentation: "
            "https://documentation.wazuh.com/current/quickstart.html#operating-system"
        )


@pytest.mark.parametrize(
    "mock_dist_name, mock_dist_version, expected_warning",
    [
        ("ubuntu", "20.04", None),
        ("centos", "8", None),
        (
            "debian",
            "10",
            "Unsupported distribution: debian_10.\n"
            "                       The current system does not match with the list of recommended systems. The installation may not work properly.\n"
            "                       Please check the documentation for more information: https://documentation.wazuh.com/current/quickstart.html#operating-system",
        ),
    ],
    ids=["supported_ubuntu", "supported_centos", "unsupported_debian"],
)
def test_check_distribution(mock_logger, mock_dist_name, mock_dist_version, expected_warning):
    with patch("distro.id", return_value=mock_dist_name), patch("distro.version", return_value=mock_dist_version):
        check_distribution()

        if expected_warning:
            mock_logger.warning.assert_called_once_with(expected_warning)
        else:
            mock_logger.warning.assert_not_called()


@pytest.mark.parametrize(
    "mock_package_manager, expected_manager",
    [
        ("apt", PackageManager.APT),
        ("yum", PackageManager.YUM),
    ],
)
def test_check_package_manager_supported(mock_package_manager, expected_manager):
    with patch("shutil.which", return_value=mock_package_manager) as mock_which:
        if mock_package_manager == "apt":
            mock_which.side_effect = (None, True)  # Only apt exists
        else:
            mock_which.side_effect = (True, None)  # Only yum exists

        assert check_package_manager() == expected_manager


def test_check_package_manager_unsupported():
    with patch("shutil.which", return_value="nonexistent_package_manager") as mock_which:
        mock_which.side_effect = (None, None)  # Neither apt nor yum exists
        with pytest.raises(SystemNotSupportedError) as exc_info:
            check_package_manager()

        assert str(exc_info.value) == (
            "No supported package manager found (apt or yum/rpm). "
            "Please checks the permitted operating systems in the documentation: "
            "https://documentation.wazuh.com/current/quickstart.html#operating-system"
        )
