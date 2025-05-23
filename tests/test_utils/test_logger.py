import logging
import os
from unittest.mock import patch

import pytest
from rich.color import Color, ColorType
from rich.logging import RichHandler
from rich.style import Style

from utils.logger import Logger, StripRichMarkupFormatter


@pytest.fixture
def mock_my_logger():
    with (
        patch.object(logging.Logger, "error") as mock_error,
        patch.object(logging.Logger, "info") as mock_info,
        patch.object(logging.Logger, "debug") as mock_debug,
        patch.object(logging.FileHandler, "_open"),
        patch("os.makedirs") as mock_makedirs,
    ):
        logger = Logger("test_logger")

        logger.mock_error = mock_error  # type: ignore
        logger.mock_info = mock_info  # type: ignore
        logger.mock_debug = mock_debug  # type: ignore
        logger.mock_makedirs = mock_makedirs  # type: ignore

        yield logger


def test_console_logger_initialization(mock_my_logger):
    assert mock_my_logger.name == "test_logger"

    assert mock_my_logger.level == logging.DEBUG

    handler = mock_my_logger.handlers[0]
    assert isinstance(handler, RichHandler)
    formatter = handler.formatter

    assert formatter
    assert isinstance(formatter._style, logging.StrFormatStyle)
    assert formatter._style._fmt == "{name}: {message}"
    assert handler.console._thread_locals.theme_stack._entries[0]["repr.str"] == Style()
    assert handler.console._thread_locals.theme_stack._entries[0]["repr.ipv4"] == Style()
    assert handler.console._thread_locals.theme_stack._entries[0]["logging.level.debug"] == Style(
        color=Color("default", ColorType.DEFAULT)
    )


def test_file_logger_initialization(mock_my_logger):
    assert len(mock_my_logger.handlers) == 2

    file_handler = mock_my_logger.handlers[1]
    assert isinstance(file_handler, logging.FileHandler)
    assert file_handler.baseFilename == os.path.expanduser("~/.wazuh-installation-assistant/log/wazuh-install.log")
    assert mock_my_logger.mock_makedirs.call_count == 1
    assert isinstance(file_handler.formatter, StripRichMarkupFormatter)


@pytest.mark.parametrize(
    "message, expected",
    [
        ("[green]Test message[/green]", "Test message"),
        ("[bold]Bold[/bold] and [italic]italic[/italic] text", "Bold and italic text"),
        ("Plain message", "Plain message"),
    ],
)
def test_strip_rich_markup_formatter(message, expected):
    formatter = StripRichMarkupFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test_path",
        lineno=10,
        msg=message,
        args=None,
        exc_info=None,
    )
    clean_message = formatter.format(record)

    assert expected in clean_message


def test_logger_info_success(mock_my_logger):
    mock_my_logger.info_success("Test message")

    mock_my_logger.mock_info.assert_called_with("[green]✓ Test message[/green]")


def test_logger_error(mock_my_logger):
    mock_my_logger.error("Test message")

    mock_my_logger.mock_error.assert_called_once_with("[red]✗ Test message[/red]", exc_info=False)


def test_logger_debug_title(mock_my_logger):
    mock_my_logger.debug_title("Test message")

    mock_my_logger.mock_debug.assert_called_once_with("[bold]---- Test message ----[/bold]")
