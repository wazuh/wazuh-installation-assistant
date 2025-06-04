from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
import requests
from rich.console import Console
from rich.progress import BarColumn, SpinnerColumn, TextColumn, TimeRemainingColumn, TransferSpeedColumn

from installation_assistant.managers.utils.helpers import (
    download_package_with_progress_bar,
    exec_command,
    install_package_with_spinner,
    remove_url_parameters,
)


@pytest.fixture
def mock_logger():
    return MagicMock()


@pytest.fixture
def mock_exec_command():
    with patch("installation_assistant.managers.utils.helpers.exec_command") as mock_exec:
        yield mock_exec


@pytest.fixture
def mock_command():
    return "test_command"


@pytest.fixture
def mock_package_name():
    return "test_package"


@pytest.fixture
def mock_destination_path():
    return Path("/tmp/test_package")


@pytest.fixture
def mock_package_url():
    return "https://example.com/test_package.zip"


@pytest.fixture
def mock_request():
    with patch("installation_assistant.managers.utils.helpers.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.iter_content = MagicMock(return_value=[b"chunk1", b"chunk2"])
        mock_response.headers = {"content-length": "16"}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value.__enter__.return_value = mock_response
        yield mock_get


@pytest.fixture
def mock_progress_bar():
    with patch("installation_assistant.managers.utils.helpers.Progress") as mock_progress:
        mock_progress.return_value.add_task = MagicMock()
        mock_progress.return_value.__enter__.return_value = mock_progress.return_value
        yield mock_progress


@pytest.mark.parametrize(
    "raw_url, formatted_url",
    [
        ("https://example.com/path/to/file", "https://example.com/path/to/file"),
        ("https://example.com/path/to/file?param=value", "https://example.com/path/to/file"),
    ],
)
@patch("installation_assistant.managers.utils.helpers.open", new_callable=mock_open)
def test_download_package_with_progress_bar_success(
    mock_open, mock_request, mock_logger, mock_destination_path, raw_url, formatted_url, mock_progress_bar
):
    download_package_with_progress_bar(mock_logger, mock_destination_path, raw_url)

    assert mock_progress_bar.call_count == 1
    assert isinstance(mock_progress_bar.call_args_list[0].args[0], TextColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].args[1], SpinnerColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].args[2], TextColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].args[3], BarColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].args[4], str)
    assert isinstance(mock_progress_bar.call_args_list[0].args[5], str)
    assert isinstance(mock_progress_bar.call_args_list[0].args[6], TransferSpeedColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].args[7], str)
    assert isinstance(mock_progress_bar.call_args_list[0].args[8], TimeRemainingColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].kwargs["console"], Console)
    assert isinstance(mock_progress_bar.call_args_list[0].kwargs["transient"], bool)
    assert mock_progress_bar.call_args_list[0].args[0].text_format == "                   "
    assert mock_progress_bar.call_args_list[0].args[4] == "[progress.percentage]{task.percentage:>3.1f}%"
    assert mock_progress_bar.call_args_list[0].args[5] == "•"
    assert mock_progress_bar.call_args_list[0].args[7] == "•"
    assert mock_progress_bar.call_args_list[0].kwargs["transient"]
    assert mock_progress_bar.call_args_list[0].args[2].text_format == "[bold blue]{task.fields[filename]}"
    assert mock_progress_bar.call_args_list[0].args[2].justify == "right"
    mock_progress_bar.return_value.add_task.assert_called_once_with(
        f"Downloading {mock_destination_path.name}",
        total=16,  # Total size in bytes from mock_request
        filename=mock_destination_path.name,
    )

    mock_logger.debug.assert_any_call(f"Starting download from: {formatted_url}")
    mock_logger.info_success.assert_called_once_with(f"Download completed and saved to '{mock_destination_path}'.")

    mock_request.assert_called_once_with(raw_url, stream=True, allow_redirects=True)
    mock_request.return_value.__enter__.return_value.iter_content.assert_called_once_with(chunk_size=8192)

    mock_open.assert_called_once_with(mock_destination_path, "wb")
    assert (
        mock_open.return_value.write.call_count == 2
    )  # Two chunks written, since the total size is 16 bytes and we are using 8KB chunks.


@patch("installation_assistant.managers.utils.helpers.open", new_callable=mock_open)
def test_download_package_with_progress_bar_without_chunks(
    mock_open, mock_request, mock_logger, mock_destination_path, mock_package_url, mock_progress_bar
):
    mock_request.return_value.__enter__.return_value.headers = {"content-length": "0"}
    mock_request.return_value.__enter__.return_value.iter_content = MagicMock(return_value=[])

    download_package_with_progress_bar(mock_logger, mock_destination_path, mock_package_url)

    assert mock_progress_bar.call_count == 1
    mock_progress_bar.return_value.add_task.assert_called_once_with(
        f"Downloading {mock_destination_path.name}",
        total=0,  # Total size in bytes from mock_request
        filename=mock_destination_path.name,
    )
    assert mock_open.return_value.write.call_count == 0
    mock_request.return_value.__enter__.return_value.iter_content.assert_called_once_with(
        chunk_size=8192
    )  # Ensure iter_content is called with the correct chunk size, although no chunks are returned.


@pytest.mark.parametrize(
    "raw_url, formatted_url",
    [
        ("https://example.com/path/to/file", "https://example.com/path/to/file"),
        ("https://example.com/path/to/file?param=value", "https://example.com/path/to/file"),
    ],
)
@patch("installation_assistant.managers.utils.helpers.requests.get")
def test_download_package_with_progress_bar_http_error(
    mock_requests_get, mock_logger, mock_destination_path, raw_url, formatted_url
):
    mock_requests_get.side_effect = requests.HTTPError(f"HTTP Error: 403 Forbidden for {raw_url}")

    with pytest.raises(requests.HTTPError):
        download_package_with_progress_bar(mock_logger, mock_destination_path, raw_url)

    mock_logger.error.assert_called_once_with(
        f"Error downloading {formatted_url}: HTTP Error: 403 Forbidden for {formatted_url}"
    )


@patch("installation_assistant.managers.utils.helpers.open", new_callable=mock_open)
def test_download_package_with_progress_bar_os_error(
    mock_open, mock_request, mock_logger, mock_destination_path, mock_package_url
):
    mock_open.side_effect = OSError("OS Error")

    with pytest.raises(OSError):
        download_package_with_progress_bar(mock_logger, mock_destination_path, mock_package_url)

    mock_logger.error.assert_called_once_with(f"OS error saving file to '{mock_destination_path}': OS Error")


def test_download_package_with_progress_bar_unexpected_error(
    mock_request, mock_logger, mock_destination_path, mock_package_url
):
    mock_request.side_effect = Exception("Unexpected Error")

    with pytest.raises(Exception):  # noqa: B017
        download_package_with_progress_bar(mock_logger, mock_destination_path, mock_package_url)

    mock_logger.error.assert_called_once_with("An unexpected error occurred during download: Unexpected Error")


def test_install_package_with_spinner_success(
    mock_logger, mock_command, mock_package_name, mock_exec_command, mock_progress_bar
):
    mock_exec_command.return_value = ("Installation successful", "", 0)

    install_package_with_spinner(mock_logger, mock_command, mock_package_name)

    assert mock_progress_bar.call_count == 1
    assert isinstance(mock_progress_bar.call_args_list[0].args[0], TextColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].args[1], SpinnerColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].args[2], TextColumn)
    assert isinstance(mock_progress_bar.call_args_list[0].kwargs["console"], Console)
    assert isinstance(mock_progress_bar.call_args_list[0].kwargs["transient"], bool)
    assert mock_progress_bar.call_args_list[0].args[0].text_format == "                   "
    assert mock_progress_bar.call_args_list[0].args[2].text_format == "[progress.description]{task.description}"
    assert mock_progress_bar.call_args_list[0].args[1].spinner.name == "dots"
    assert mock_progress_bar.call_args_list[0].kwargs["transient"]
    mock_progress_bar.return_value.add_task.assert_called_once_with("Installing [bold]test_package[/bold]")
    mock_progress_bar.return_value.update.assert_called_once_with(mock_progress_bar.return_value.add_task.return_value)
    mock_exec_command.assert_called_once_with(mock_command)


def test_install_package_with_spinner_already_installed(
    mock_logger, mock_command, mock_package_name, mock_exec_command, mock_progress_bar
):
    mock_exec_command.return_value = ("Package is already installed", "", 0)

    install_package_with_spinner(mock_logger, mock_command, mock_package_name)

    mock_progress_bar.return_value.add_task.assert_called_once_with(f"Installing [bold]{mock_package_name}[/bold]")
    mock_exec_command.assert_called_once_with(mock_command)
    mock_logger.info.assert_called_once_with(
        f"{mock_package_name.capitalize().replace('_', ' ')} is already installed."
    )


def test_install_package_with_spinner_runtime_error(
    mock_logger, mock_command, mock_package_name, mock_exec_command, mock_progress_bar
):
    mock_exec_command.return_value = ("", "Installation failed", 1)

    with pytest.raises(RuntimeError, match=f"Failed to install {mock_package_name}: Installation failed"):
        install_package_with_spinner(mock_logger, mock_command, mock_package_name)

    mock_progress_bar.return_value.add_task.assert_called_once_with(f"Installing [bold]{mock_package_name}[/bold]")
    mock_exec_command.assert_called_once_with(mock_command)
    mock_logger.error.assert_called_once_with(
        f"Failed while installing {mock_package_name}: Failed to install {mock_package_name}: Installation failed"
    )


@pytest.mark.parametrize(
    "command, mock_stdout, mock_stderr, mock_returncode",
    [
        ("echo 'Hello, World!'", "Hello, World!\n", "", 0),
        ("ls non_existent_directory", "", "ls: cannot access 'non_existent_directory': No such file or directory\n", 2),
        ("exit 1", "", "", 1),
    ],
)
@patch("installation_assistant.managers.utils.helpers.subprocess.run")
def test_exec_command(mock_subprocess_run, command, mock_stdout, mock_stderr, mock_returncode):
    mock_result = MagicMock()
    mock_result.stdout = mock_stdout
    mock_result.stderr = mock_stderr
    mock_result.returncode = mock_returncode
    mock_subprocess_run.return_value = mock_result

    output, error_output, returncode = exec_command(command)

    mock_subprocess_run.assert_called_once_with(command, shell=True, capture_output=True, text=True)
    assert output == mock_stdout
    assert error_output == mock_stderr
    assert returncode == mock_returncode


@pytest.mark.parametrize(
    "url, expected_result",
    [
        ("https://example.com/path/to/file", "https://example.com/path/to/file"),
        ("https://example.com/path/to/file?param=value", "https://example.com/path/to/file"),
        ("https://example.com/path/to/file?param1=value1&param2=value2", "https://example.com/path/to/file"),
        ("https://example.com/path/to/file#", "https://example.com/path/to/file#"),
        ("https://example.com/path/to/file?param=value#", "https://example.com/path/to/file"),
        ("https://example.com/path/to/file?param=value&", "https://example.com/path/to/file"),
        ("https://example.com/path/to/file?", "https://example.com/path/to/file"),
    ],
)
def test_remove_url_parameters(url, expected_result):
    result = remove_url_parameters(url)
    assert result == expected_result
