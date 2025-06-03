import subprocess
from pathlib import Path

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn, TransferSpeedColumn

from utils import Logger


def download_package_with_progress_bar(logger: Logger, destination_path: Path, package_url: str) -> None:
    """
    Downloads a file from the specified URL and saves it to the given destination path,
    displaying a progress bar during the download process.

    Args:
        logger (Logger): Logger instance for logging messages.
        destination_path (Path): Path object representing the destination file path where the downloaded file will be saved.
        package_url (str): URL of the package to be downloaded.

    Notes:
        - The function uses the `rich` library to display a progress bar.
        - If the `Content-Length` header is not available in the response, the total file size will not be displayed.
        - The function writes the file in chunks of 8KB to handle large files efficiently.

    Returns:
        None: This function does not return any value. It logs the progress and results of the download.
    """

    console = Console()
    formatted_url = remove_url_parameters(package_url)

    try:
        with requests.get(package_url, stream=True, allow_redirects=True) as response:
            response.raise_for_status()  # Raise an HTTPError for 4xx/5xx responses

            # Get the total file size from headers (if available)
            total_size_bytes = int(response.headers.get("content-length", 0))
            filename = destination_path.name

            logger.debug(f"Starting download from: {formatted_url}")
            logger.debug(f"Saving to '{destination_path}'")
            if total_size_bytes > 0:
                logger.debug(f"Expected file size: {total_size_bytes / (1024 * 1024):.2f} MB")
            else:
                logger.warning("Could not get total file size (Content-Length not available).")

            # Create a progress bar using rich
            with Progress(
                TextColumn("                   "),
                SpinnerColumn(),
                TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
                BarColumn(bar_width=30),
                "[progress.percentage]{task.percentage:>3.1f}%",
                "•",
                TransferSpeedColumn(),
                "•",
                TimeRemainingColumn(),
                console=console,
                transient=True,
            ) as progress:
                task_id = progress.add_task(f"Downloading {filename}", total=total_size_bytes, filename=filename)

                with open(destination_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):  # 8KB chunks
                        if chunk:  # Filter out empty keep-alive chunks
                            f.write(chunk)
                            # Update the task's progress
                            progress.update(task_id, advance=len(chunk))

            logger.info_success(f"Download completed and saved to '{destination_path}'.")

    except requests.RequestException as e:
        error_message = str(e)
        formatted_url = remove_url_parameters(formatted_url)

        if package_url in error_message:
            error_message = error_message.replace(package_url, formatted_url)

        logger.error(f"Error downloading {formatted_url}: {error_message}")
        raise requests.HTTPError(error_message) from None
    except OSError as e:
        logger.error(f"OS error saving file to '{destination_path}': {e}")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred during download: {e}")
        raise


def install_package_with_spinner(logger: Logger, command: str, package_name: str) -> None:
    """
    Installs a package using a command-line tool while displaying a spinner in the console.

    Args:
        logger (Logger): Logger instance to log messages.
        command (str): The command to execute for installing the package.
        package_name (str): The name of the package to be installed.

    Notes:
        - The function uses the `rich` library to display a spinner during the installation.

    Returns:
        None: This function does not return any value. It logs the progress and results of the installation.
    """

    console = Console()

    with Progress(
        TextColumn("                   "),
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(f"Installing [bold]{package_name}[/bold]")
        progress.update(task_id)

        try:
            output, error_output, returncode = exec_command(command)
            if error_output and returncode != 0:
                raise RuntimeError(f"Failed to install {package_name}: {error_output}")
            elif "already installed" in output:
                logger.info(f"{package_name.capitalize().replace('_', ' ')} is already installed.")
        except Exception as e:
            logger.error(f"Failed while installing {package_name}: {e}")
            raise


def exec_command(command: str) -> tuple[str, str, int]:
    """
    Executes a shell command and captures its output, error output, and return code.

    Args:
        command (str): The shell command to execute.

    Returns:
        tuple[str, str, int]: A tuple containing:
            - output (str): The standard output of the command.
            - error_output (str): The standard error output of the command.
            - returncode (int): The return code of the command execution.
    """

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    output = result.stdout
    error_output = result.stderr
    returncode = result.returncode

    return output, error_output, returncode


def remove_url_parameters(url: str) -> str:
    """
    Removes URL parameters from a given URL.

    Args:
        url (str): The URL from which to remove parameters.

    Returns:
        str: The URL without parameters.
    """
    if "?" in url:
        return url.split("?")[0]
    return url
