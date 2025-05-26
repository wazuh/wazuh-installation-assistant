import logging
import os

from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text
from rich.theme import Theme


class StripRichMarkupFormatter(logging.Formatter):
    def __init__(self):
        fmt = "{asctime} [{levelname:^7}] {name}: {message}"
        datefmt = "%Y-%m-%d %H:%M:%S"
        style = "{"
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)

    def format(self, record):
        formatted_message = super().format(record)

        text_obj = Text.from_markup(formatted_message)

        clean_formatted_message = str(text_obj.plain)

        return clean_formatted_message


class Logger(logging.Logger):
    """
    Custom Logger class that extends the standard logging.Logger to provide additional functionality
    with colored output for different log levels.
    """

    def __init__(self, name: str, log_file: str = "~/.wazuh-installation-assistant/log/wazuh-install.log"):
        """
        Initialize the logger with the specified name.

        Args:
            name (str): The name of the logger.

        The logger is set to the DEBUG level and a StreamHandler with a custom formatter is added to it.
        """
        super().__init__(name)
        self.setLevel(logging.DEBUG)

        log_file = os.path.expanduser(log_file)
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        console = Console(theme=Theme({"logging.level.debug": "default", "repr.str": "none", "repr.ipv4": "none"}))
        rich_handler = RichHandler(markup=True, console=console, log_time_format="%Y-%m-%d %H:%M:%S", show_path=False)
        rich_handler.setFormatter(logging.Formatter(fmt="{name}: {message}", style="{"))
        self.addHandler(rich_handler)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(StripRichMarkupFormatter())
        self.addHandler(file_handler)

    def info_success(self, message: str):
        """
        Logs a success message modifying the default INFO log adding a check marks in the beggining of
        the log and colored it with a green color.

        Args:
            message (str): The success message to log.
        """
        self.info(f"[green]✓ {message}[/green]")

    def error(self, message: str, exc_info: bool = False):
        """
        Logs an error message modifying the default ERROR log with a cross symbol.

        Args:
            message (str): The error message to be logged.
        """
        super().error(f"[red]✗ {message}[/red]", exc_info=exc_info)

    def debug_title(self, message: str):
        """
        Logs a debug message modifying the default DEBUG log with a formatted title.

        Args:
            message (str): The message to be logged as a title.
        """
        self.debug(f"[bold]---- {message} ----[/bold]")
