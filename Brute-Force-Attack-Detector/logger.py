"""
logger.py
Centralized logging configuration for the application.
Writes to logs/app.log and also streams to console.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

import constants

_LOGGER_NAME = "brute_force_detector"
_configured = False


def get_logger(name: str = _LOGGER_NAME) -> logging.Logger:
    """Return a configured logger instance. Safe to call multiple times."""
    global _configured

    logger = logging.getLogger(name)

    if not _configured:
        Path(constants.LOGS_DIR).mkdir(parents=True, exist_ok=True)
        logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        file_handler = RotatingFileHandler(
            constants.APP_LOG_FILE, maxBytes=2_000_000, backupCount=3
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.propagate = False

        _configured = True

    return logger
