import os
from pathlib import Path

from installation_assistant.checks import check_architecture, check_package_manager
from installation_assistant.utils import ComponentArch, PackageManager, PackageType
from utils import Component, Logger

from .utils import (
    download_package_with_progress_bar,
    format_component_urls_file,
    install_package_with_spinner,
)

logger = Logger("PackagesManager")


class PackagesManager:
    def __init__(self, packages_url_file: Path):
        """
        Initialize the PackagesManager instance. This class is responsible for managing package downloads and installations for Wazuh components.
        It detects the system's package manager (APT or YUM), architecture, and package type (DEB or RPM) based on the OS.

        Args:
            packages_url_file (Path): Path to the file containing package URLs.

        Attributes:
            packages_url_file (Path): Stores the path to the file containing package URLs.
            package_manager (PackageManager): The package manager detected on the system (e.g., APT or YUM).
            arch (str): The system architecture (e.g., x86_64, arm64).
            package_type (PackageType): The type of package based on the package manager (DEB for APT, RPM for YUM).
        """

        self.packages_url_file = packages_url_file
        self.package_manager = check_package_manager()
        self.arch = self._get_system_arch()
        self.package_type = PackageType.DEB if self.package_manager is PackageManager.APT else PackageType.RPM

    def _get_system_arch(self) -> ComponentArch:
        """
        Determine the system architecture based on the package manager and the detected architecture.

        Returns:
            ComponentArch: The system architecture. If the package manager is APT, it returns AMD64 for x86_64 and ARM64 for AARCH64.
            If the package manager is YUM, it returns X86_64 for AMD64 and AARCH64 for ARM64.
            This is done because of the naming convention used by Wazuh in its packages.

        """
        arch = check_architecture()

        if self.package_manager is PackageManager.APT and arch == ComponentArch.X86_64:
            return ComponentArch.AMD64
        elif self.package_manager is PackageManager.APT and arch == ComponentArch.AARCH64:
            return ComponentArch.ARM64
        elif self.package_manager is PackageManager.YUM and arch == ComponentArch.AMD64:
            return ComponentArch.X86_64
        elif self.package_manager is PackageManager.YUM and arch == ComponentArch.ARM64:
            return ComponentArch.AARCH64
        else:
            return arch

    def get_component_package_url(self, component: Component) -> str:
        """
        Retrieve the URL for a specific component package based on its type and architecture from the `self.packages_url_file` file.

        Args:
            component (Component): The component for which the package URL is being fetched.

        Returns:
            str: The URL of the package for the specified component.
        """

        logger.debug(
            f"Fetching URLs for the {component.replace('_', ' ')} component with package type '{self.package_type}' and '{self.arch}' architecture"
        )

        component_urls = format_component_urls_file(self.packages_url_file).get(component)

        if not component_urls:
            raise ValueError(f"No URLs found for component {component} in {self.packages_url_file}")

        component_urls_by_package_type = component_urls.get(self.package_type)
        if not component_urls_by_package_type:
            raise ValueError(
                f"No URLs found for component {component} with {self.package_type} package type in {self.packages_url_file}"
            )

        component_urls_by_arch = component_urls_by_package_type.get(self.arch)
        if not component_urls_by_arch:
            raise ValueError(
                f"No URLs found for component {component} with {self.package_type} package type and {self.arch} architecture in {self.packages_url_file}"
            )

        return component_urls_by_arch

    def download_package_from_url(
        self, package_url: str, destination_path: str | Path, component: Component | None = None
    ) -> None:
        """
        Downloads a package from the specified URL and saves it to the given destination path.
        Args:
            package_url (str): The URL of the package to download.
            destination_path (str | Path): The path where the downloaded package will be saved.
            component (Component | None, optional): The component associated with the package. If not provided,
                the component name will be inferred from the URL.

        Returns:
            None: This function does not return any value. It logs the progress and results of the download.
        """

        logger.debug("Downloading package for the given URL")

        component_name = None
        try:
            if component:
                component_name = component
            else:
                for component in Component:
                    if component.split("_")[1] in package_url:
                        component_name = component
                        break
            if not component_name:
                raise ValueError(
                    "Could not determine component name from URL. The given URL must have the component name in it"
                )
        except ValueError as e:
            logger.error(f"Error while downloading package: {e}")
            raise

        destination_path = Path(destination_path) / f"{component_name}.{self.package_type}"
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)

        download_package_with_progress_bar(logger=logger, package_url=package_url, destination_path=destination_path)

        logger.info_success(f"{component_name.capitalize().replace('_', ' ')} package downloaded successfully")

    def download_package_from_component(self, component: Component, destination_path: str | Path) -> None:
        """
        Downloads a package associated with a given component and saves it to the specified destination path.

        Args:
            component (Component): The component for which the package needs to be downloaded.
            destination_path (str | Path): The file path where the downloaded package will be saved
        """

        package_url = self.get_component_package_url(component)
        self.download_package_from_url(package_url, destination_path=destination_path, component=component)

    def install_package(self, package_path: str | Path, component: Component | None = None) -> None:
        """
        Install a package from the given path using the system's package manager.

        Args:
            component (Component): The component for which the package is being installed.
            package_path (str | Path): The path to the package file to be installed.

        Returns:
            None: This function does not return any value. It logs the progress and results of the installation.
        """

        component_name = None
        try:
            if component:
                component_name = component
            else:
                for component in Component:
                    if component.split("_")[1] in Path(package_path).name:
                        component_name = component
                        break
            if not component_name:
                raise ValueError(
                    f"The given package {Path(package_path).name} path must have the wazuh component name in it to install it ({', '.join([c.split('_')[1] for c in Component])})"
                )
        except ValueError as e:
            logger.error(f"Error while downloading package: {e}")
            raise

        logger.debug(f"Installing {component_name} from '{package_path}' ...")

        command = ""
        if self.package_manager == PackageManager.APT:
            command += f"dpkg -i {package_path} && apt-get install -f"
        elif self.package_manager == PackageManager.YUM:
            command += f"yum install -y {package_path}"
        else:
            raise ValueError(
                f"Unsupported package manager: {self.package_manager}. Cannot install {component_name} from {package_path}"
            )

        install_package_with_spinner(logger=logger, command=command, package_name=component_name)

        logger.info_success(f"{component_name.capitalize().replace('_', ' ')} installed successfully")
