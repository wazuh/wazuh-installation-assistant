import os

from utils.logger import Logger

logger = Logger("GlobalChecks")


def check_if_sudo() -> None:
    """
    Check if the module is being run with superuser privileges.

    Returns:
        None: If the module is run with superuser privileges.
    Raises:
        PermissionError: If the module is not run with superuser privileges.
    """

    try:
        if os.geteuid() != 0:
            raise PermissionError(
                "The installation assistant module must be run with superuser privileges (sudo). Please try again with 'sudo'."
            )
    except PermissionError as e:
        logger.error(f"Permission error: {e}")
        raise
