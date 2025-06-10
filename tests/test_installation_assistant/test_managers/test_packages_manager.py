import os
from pathlib import Path
from unittest.mock import patch

import pytest

from installation_assistant.managers.packages_manager import PackagesManager
from installation_assistant.utils import ComponentArch, PackageManager, PackageType


@pytest.fixture
def mock_packages_url_file():
    return Path("/path/to/mock/packages_url_file")


@pytest.fixture
def mock_logger():
    with patch("installation_assistant.managers.packages_manager.logger") as mock_logger:
        yield mock_logger


def mock_packages_manager(arch, package_manager, url_file=Path("/path/to/mock/packages_url_file")):
    """
    Mock function to create a PackagesManager instance with specified architecture,
    package manager, and package type.
    """
    with (
        patch("installation_assistant.managers.packages_manager.check_package_manager") as mock_check_package_manager,
        patch(
            "installation_assistant.managers.packages_manager.PackagesManager._get_system_arch"
        ) as mock_get_system_arch,
    ):
        mock_check_package_manager.return_value = package_manager
        mock_get_system_arch.return_value = arch

        return PackagesManager(url_file)


def test_init_with_apt(mock_packages_url_file):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    assert manager.packages_url_file == mock_packages_url_file
    assert manager.package_manager == PackageManager.APT
    assert manager.arch == ComponentArch.AMD64
    assert manager.package_type == PackageType.DEB


def test_init_with_yum(mock_packages_url_file):
    manager = mock_packages_manager(ComponentArch.X86_64, PackageManager.YUM)

    assert manager.packages_url_file == mock_packages_url_file
    assert manager.package_manager == PackageManager.YUM
    assert manager.arch == ComponentArch.X86_64
    assert manager.package_type == PackageType.RPM


def test_get_system_arch_with_apt_x86_64(mock_packages_url_file):
    manager = mock_packages_manager(ComponentArch.X86_64, PackageManager.APT)
    result = manager._get_system_arch()

    assert result == ComponentArch.AMD64


@patch("installation_assistant.managers.packages_manager.check_architecture")
@patch("installation_assistant.managers.packages_manager.check_package_manager")
def test_get_system_arch_with_apt_aarch64(mock_check_package_manager, mock_check_architecture, mock_packages_url_file):
    mock_check_package_manager.return_value = PackageManager.APT
    mock_check_architecture.return_value = ComponentArch.AARCH64

    manager = PackagesManager(mock_packages_url_file)
    result = manager._get_system_arch()

    assert result == ComponentArch.ARM64


@patch("installation_assistant.managers.packages_manager.check_architecture")
@patch("installation_assistant.managers.packages_manager.check_package_manager")
def test_get_system_arch_with_yum_amd64(mock_check_package_manager, mock_check_architecture, mock_packages_url_file):
    mock_check_package_manager.return_value = PackageManager.YUM
    mock_check_architecture.return_value = ComponentArch.AMD64

    manager = PackagesManager(mock_packages_url_file)
    result = manager._get_system_arch()

    assert result == ComponentArch.X86_64


@patch("installation_assistant.managers.packages_manager.check_architecture")
@patch("installation_assistant.managers.packages_manager.check_package_manager")
def test_get_system_arch_with_yum_arm64(mock_check_package_manager, mock_check_architecture, mock_packages_url_file):
    mock_check_package_manager.return_value = PackageManager.YUM
    mock_check_architecture.return_value = ComponentArch.ARM64

    manager = PackagesManager(mock_packages_url_file)
    result = manager._get_system_arch()

    assert result == ComponentArch.AARCH64


@patch("installation_assistant.managers.packages_manager.check_architecture")
@patch("installation_assistant.managers.packages_manager.check_package_manager")
def test_get_system_arch_with_yum_aarch64(mock_check_package_manager, mock_check_architecture, mock_packages_url_file):
    mock_check_package_manager.return_value = PackageManager.YUM
    mock_check_architecture.return_value = ComponentArch.AARCH64

    manager = PackagesManager(mock_packages_url_file)
    result = manager._get_system_arch()

    assert result == ComponentArch.AARCH64


@patch("installation_assistant.managers.packages_manager.check_architecture")
@patch("installation_assistant.managers.packages_manager.check_package_manager")
def test_get_system_arch_with_apt_arm64(mock_check_package_manager, mock_check_architecture, mock_packages_url_file):
    mock_check_package_manager.return_value = PackageManager.APT
    mock_check_architecture.return_value = ComponentArch.ARM64

    manager = PackagesManager(mock_packages_url_file)
    result = manager._get_system_arch()

    assert result == ComponentArch.ARM64


@patch("installation_assistant.managers.packages_manager.format_component_urls_file")
def test_get_component_package_url_success(mock_format_component_urls_file, mock_packages_url_file, mock_logger):
    # Mock the formatted URLs
    mock_format_component_urls_file.return_value = {
        "component_name": {PackageType.DEB: {ComponentArch.AMD64: "http://example.com/component_name_amd64.deb"}}
    }

    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    result = manager.get_component_package_url("component_name")  # type: ignore

    assert result == "http://example.com/component_name_amd64.deb"
    mock_format_component_urls_file.assert_called_once_with(mock_packages_url_file)
    mock_logger.debug.assert_called_with(
        "Fetching URLs for the component name component with package type 'deb' and 'amd64' architecture"
    )


@patch("installation_assistant.managers.packages_manager.format_component_urls_file")
def test_get_component_package_url_no_component(mock_format_component_urls_file, mock_logger):
    mock_format_component_urls_file.return_value = {}

    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    with pytest.raises(ValueError, match="No URLs found for component component_name in"):
        manager.get_component_package_url("component_name")  # type: ignore

    mock_logger.debug.assert_called_with(
        "Fetching URLs for the component name component with package type 'deb' and 'amd64' architecture"
    )


@patch("installation_assistant.managers.packages_manager.format_component_urls_file")
def test_get_component_package_url_no_packages(mock_format_component_urls_file):
    mock_format_component_urls_file.return_value = {"component_name": {PackageType.DEB: {}}}

    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    with pytest.raises(ValueError, match="No URLs found for component component_name with deb package type in"):
        manager.get_component_package_url("component_name")  # type: ignore


@patch("installation_assistant.managers.packages_manager.format_component_urls_file")
def test_get_component_package_url_no_architecture(mock_format_component_urls_file, mock_logger):
    mock_format_component_urls_file.return_value = {
        "component_name": {
            PackageType.DEB: {
                ComponentArch.AMD64: "http://example.com/component_name_amd64.deb",
            }
        }
    }

    manager = mock_packages_manager(ComponentArch.ARM64, PackageManager.APT)

    with pytest.raises(
        ValueError, match="No URLs found for component component_name with deb package type and arm64 architecture in"
    ):
        manager.get_component_package_url("component_name")  # type: ignore

    mock_logger.debug.assert_called_with(
        "Fetching URLs for the component name component with package type 'deb' and 'arm64' architecture"
    )


@patch("installation_assistant.managers.packages_manager.download_package_with_progress_bar")
@patch("installation_assistant.managers.packages_manager.os.makedirs")
def test_download_package_from_url_success(mock_makedirs, mock_download_package_with_progress_bar, mock_logger):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    package_url = "http://example.com/component_name_amd64.deb"
    destination_path = "/path/to/destination"
    component = "component_name"

    manager.download_package_from_url(package_url, destination_path, component)  # type: ignore

    expected_destination = Path(destination_path) / f"{component}.{manager.package_type}"
    mock_makedirs.assert_called_once_with(os.path.dirname(expected_destination), exist_ok=True)
    mock_download_package_with_progress_bar.assert_called_once_with(
        logger=mock_logger, package_url=package_url, destination_path=expected_destination
    )


@patch("installation_assistant.managers.packages_manager.download_package_with_progress_bar")
@patch("installation_assistant.managers.packages_manager.os.makedirs")
def test_download_package_from_url_infer_component(mock_makedirs, mock_download_package_with_progress_bar, mock_logger):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    package_url = "http://example.com/component_name_amd64.deb"
    destination_path = "/path/to/destination"

    with patch("installation_assistant.managers.packages_manager.Component", ["component_name"]):
        manager.download_package_from_url(package_url, destination_path)

    expected_destination = Path(destination_path) / f"component_name.{manager.package_type}"
    mock_makedirs.assert_called_once_with(os.path.dirname(expected_destination), exist_ok=True)
    mock_download_package_with_progress_bar.assert_called_once_with(
        logger=mock_logger, package_url=package_url, destination_path=expected_destination
    )


@patch("installation_assistant.managers.packages_manager.logger")
def test_download_package_from_url_no_component_in_url(mock_logger):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    package_url = "http://example.com/unknown_component.deb"
    destination_path = "/path/to/destination"

    with (
        patch("installation_assistant.managers.packages_manager.Component", ["component_name"]),
        pytest.raises(ValueError, match="Could not determine component name from URL"),
    ):
        manager.download_package_from_url(package_url, destination_path)

    mock_logger.error.assert_called_once_with(
        "Error while downloading package: Could not determine component name from URL. The given URL must have the component name in it"
    )


@patch("installation_assistant.managers.packages_manager.download_package_with_progress_bar")
@patch("installation_assistant.managers.packages_manager.os.makedirs")
def test_download_package_from_url_creates_directory(
    mock_makedirs, mock_download_package_with_progress_bar, mock_packages_url_file
):
    manager = PackagesManager(mock_packages_url_file)
    manager.package_type = PackageType.DEB

    package_url = "http://example.com/component_name_amd64.deb"
    destination_path = "/path/to/destination"
    component = "component_name"

    manager.download_package_from_url(package_url, destination_path, component)  # type: ignore

    expected_directory = os.path.dirname(Path(destination_path) / f"{component}.{manager.package_type}")
    mock_makedirs.assert_called_once_with(expected_directory, exist_ok=True)


@patch("installation_assistant.managers.packages_manager.PackagesManager.get_component_package_url")
@patch("installation_assistant.managers.packages_manager.PackagesManager.download_package_from_url")
def test_download_package_from_component_success(mock_download_package_from_url, mock_get_component_package_url):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    component = "component_name"
    destination_path = "/path/to/destination"
    package_url = "http://example.com/component_name_amd64.deb"

    mock_get_component_package_url.return_value = package_url

    manager.download_package_from_component(component, destination_path)  # type: ignore

    mock_get_component_package_url.assert_called_once_with(component)
    mock_download_package_from_url.assert_called_once_with(
        package_url, destination_path=destination_path, component=component
    )


@patch("installation_assistant.managers.packages_manager.PackagesManager.get_component_package_url")
@patch("installation_assistant.managers.packages_manager.PackagesManager.download_package_from_url")
def test_download_package_from_component_failure(mock_download_package_from_url, mock_get_component_package_url):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    component = "component_name"
    destination_path = "/path/to/destination"

    mock_get_component_package_url.side_effect = ValueError("No URLs found for component")

    with pytest.raises(ValueError, match="No URLs found for component"):
        manager.download_package_from_component(component, destination_path)  # type: ignore

    mock_get_component_package_url.assert_called_once_with(component)
    mock_download_package_from_url.assert_not_called()


@patch("installation_assistant.managers.packages_manager.install_package_with_spinner")
def test_install_package_with_apt(mock_install_package_with_spinner, mock_logger):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    package_path = "/path/to/package.deb"
    component = "component_name"

    manager.install_package(package_path, component)  # type: ignore

    mock_logger.debug.assert_called_once_with(f"Installing {component} from '{package_path}' ...")
    mock_install_package_with_spinner.assert_called_once_with(
        logger=mock_logger,
        command=f"dpkg -i {package_path} && apt-get install -f",
        package_name=component,
    )
    mock_logger.info_success.assert_called_once_with(
        f"{component.capitalize().replace('_', ' ')} installed successfully"
    )


@patch("installation_assistant.managers.packages_manager.install_package_with_spinner")
def test_install_package_with_yum(mock_install_package_with_spinner, mock_logger):
    manager = mock_packages_manager(ComponentArch.X86_64, PackageManager.YUM)

    package_path = "/path/to/package.rpm"
    component = "component_name"

    manager.install_package(package_path, component)  # type: ignore

    mock_logger.debug.assert_called_once_with(f"Installing {component} from '{package_path}' ...")
    mock_install_package_with_spinner.assert_called_once_with(
        logger=mock_logger,
        command=f"yum install -y {package_path}",
        package_name=component,
    )
    mock_logger.info_success.assert_called_once_with(
        f"{component.capitalize().replace('_', ' ')} installed successfully"
    )


@patch("installation_assistant.managers.packages_manager.install_package_with_spinner")
def test_install_package_infer_component(mock_install_package_with_spinner, mock_logger):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    package_path = "/path/to/component_name.deb"

    with patch("installation_assistant.managers.packages_manager.Component", ["component_name"]):
        manager.install_package(package_path)

    mock_logger.debug.assert_called_once_with(f"Installing component_name from '{package_path}' ...")
    mock_install_package_with_spinner.assert_called_once_with(
        logger=mock_logger,
        command=f"dpkg -i {package_path} && apt-get install -f",
        package_name="component_name",
    )
    mock_logger.info_success.assert_called_once_with("Component name installed successfully")


def test_install_package_no_component_in_path(mock_logger):
    manager = mock_packages_manager(ComponentArch.AMD64, PackageManager.APT)

    package_path = "/path/to/unknown_component.deb"

    with (
        patch("installation_assistant.managers.packages_manager.Component", ["component_name"]),
        pytest.raises(
            ValueError, match="The given package unknown_component.deb path must have the wazuh component name in it"
        ),
    ):
        manager.install_package(package_path)

    mock_logger.error.assert_called_once_with(
        "Error while downloading package: The given package unknown_component.deb path must have the wazuh component name in it to install it (name)"
    )


def test_install_package_unsupported_package_manager(mock_logger):
    manager = mock_packages_manager(ComponentArch.AMD64, "unsupported_manager")  # type: ignore

    package_path = "/path/to/package.deb"
    component = "component_name"

    with pytest.raises(ValueError, match="Unsupported package manager: unsupported_manager"):
        manager.install_package(package_path, component)  # type: ignore

    mock_logger.debug.assert_called_once_with(f"Installing {component} from '{package_path}' ...")
