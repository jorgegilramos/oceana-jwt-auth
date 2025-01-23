import os
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from ..config import OCEANA_API_LOGGING_DIR, OCEANA_API_LOGGING_FILE, OCEANA_API_LOGGING_WHEN, \
    OCEANA_API_LOGGING_INTERVAL, OCEANA_API_LOGGING_TITLE, OCEANA_API_LOGGING_LEVEL


class AppLogger:
    """
    A singleton class for application logging.

    This class configures a logger to write logs to a file and console with specified formatting.
    It uses a TimedRotatingFileHandler for log files to rotate them at midnight and keeps 7 days of backup.
    The logger is configured to be a singleton to ensure that only one instance is used throughout the application.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        Ensures that only one instance of the class is created.
        """
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, name):
        """
        Initializes the logger with file and console handlers if not already initialized.

        Args:
            - name: The name of the logger, typically the __name__ of the module creating the logger.
        """
        # Prevent re-initialization if already initialized
        if hasattr(self, "logger"):
            return
        # Configuration settings from the config (YAML file)
        self.log_dir = OCEANA_API_LOGGING_DIR
        self.log_file = OCEANA_API_LOGGING_FILE

        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.propagate = False

        if not self.logger.handlers:
            level = getattr(logging, OCEANA_API_LOGGING_LEVEL.upper(), logging.INFO)
            self.logger.setLevel(level)

            logFormatter = logging.Formatter(
                "%(asctime)s - [%(name)s] - %(levelname)-5s - %(message)s"
            )

            Path(self.log_dir).mkdir(parents=True, exist_ok=True)
            file_path = os.path.join(self.log_dir, self.log_file)
            fileHandler = TimedRotatingFileHandler(
                file_path,
                when=OCEANA_API_LOGGING_WHEN,
                interval=OCEANA_API_LOGGING_INTERVAL,
            )
            fileHandler.suffix = "%Y%m%d_%H%M%S.log"
            fileHandler.setFormatter(logFormatter)

            self.logger.addHandler(fileHandler)

            consoleHandler = logging.StreamHandler()
            consoleHandler.setFormatter(logFormatter)
            self.logger.addHandler(consoleHandler)

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)


logger = AppLogger(OCEANA_API_LOGGING_TITLE)
