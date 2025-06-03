import platform
import shutil

import distro

from installation_assistant.utils import ComponentArch, PackageManager
from utils import Logger

from .utils import SupportedDistribution

logger = Logger("PackagesInstallationChecks")


class SystemNotSupportedError(Exception):
    """Custom exception for unsupported distributions."""

    def __init__(self, message: str):
        documentation_message = "Please checks the permitted operating systems in the documentation: https://documentation.wazuh.com/current/quickstart.html#operating-system"

        super().__init__(f"{message}. {documentation_message}")


def check_architecture() -> ComponentArch:
    """
    Check the system architecture and return it.

    Returns:
        ComponentArch: The architecture of the system (e.g., 'x86_64', 'arm64').
    """
    arch = platform.machine()
    for arch_type in ComponentArch:
        if arch_type in arch.lower():
            return arch_type

    raise SystemNotSupportedError(
        f"Unsupported architecture: {arch}. Only x86_64/AMD64 or AARCH64/ARM64 are supported."
    )


def check_distribution() -> None:
    """
    Checks the current operating system distribution and version against a list of supported distributions.

    If the distribution and version combination is not in the list of supported distributions,
    a warning is logged indicating that the installation may not work properly. The user is
    advised to consult the documentation for more information.

    Returns:
        None: If the distribution is supported, no action is taken.
    """

    dist_name = distro.id()
    dist_version = distro.version().replace(".", "_")
    full_dist = f"{dist_name}_{dist_version}"

    if full_dist not in SupportedDistribution:
        logger.warning(f"""Unsupported distribution: {full_dist}.
                       The current system does not match with the list of recommended systems. The installation may not work properly.
                       Please check the documentation for more information: https://documentation.wazuh.com/current/quickstart.html#operating-system""")


def check_package_manager() -> PackageManager:
    """
    Determines the package manager available on the system.

    Iterates through the supported package managers defined in the `PackageManager` enumeration
    and checks if any of them is available on the system.

    Returns:
        PackageManager: The detected package manager.

    Raises:
        SystemNotSupportedError: If no supported package manager is found on the system.
    """

    for type in PackageManager:
        if shutil.which(type):
            return type

    raise SystemNotSupportedError("No supported package manager found (apt or yum/rpm).")
