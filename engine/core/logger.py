import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime
from config import LOG_BASE_DIR


class LoggerFactory:

    @staticmethod
    def _create_log_directory(log_type: str) -> str:
        log_dir = os.path.join(LOG_BASE_DIR, log_type)
        os.makedirs(log_dir, exist_ok=True)
        return log_dir

    @staticmethod
    def get_logger(name: str, log_type: str = "scan_logs") -> logging.Logger:

        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        if logger.hasHandlers():
            return logger

        log_dir = LoggerFactory._create_log_directory(log_type)

        timestamp = datetime.now().strftime("%Y-%m-%d")
        log_file = os.path.join(log_dir, f"{name}_{timestamp}.log")

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3
        )

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )

        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger
