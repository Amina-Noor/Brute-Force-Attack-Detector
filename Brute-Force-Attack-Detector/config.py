"""
config.py
Application configuration management using dataclasses and python-dotenv.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from dotenv import load_dotenv

import constants

load_dotenv()


@dataclass
class DetectionConfig:
    """Holds all tunable detection parameters for a single analysis run."""

    failed_threshold: int = int(
        os.getenv("FAILED_THRESHOLD", constants.DEFAULT_FAILED_THRESHOLD)
    )
    time_window_minutes: int = int(
        os.getenv("TIME_WINDOW_MINUTES", constants.DEFAULT_TIME_WINDOW_MINUTES)
    )
    credential_stuffing_user_threshold: int = (
        constants.DEFAULT_CREDENTIAL_STUFFING_USER_THRESHOLD
    )
    password_spray_ip_threshold: int = constants.DEFAULT_PASSWORD_SPRAY_IP_THRESHOLD
    ignore_internal_ips: bool = False
    trusted_users: List[str] = field(default_factory=list)
    export_directory: str = os.getenv("EXPORT_DIRECTORY", constants.REPORTS_DIR)

    def __post_init__(self) -> None:
        if self.failed_threshold < 1:
            raise ValueError("failed_threshold must be >= 1")
        if self.time_window_minutes < 1:
            raise ValueError("time_window_minutes must be >= 1")
        Path(self.export_directory).mkdir(parents=True, exist_ok=True)


@dataclass
class AppConfig:
    """Global application configuration."""

    app_name: str = "Brute Force Attack Detector"
    version: str = "1.0.0"
    log_dir: str = constants.LOGS_DIR
    reports_dir: str = constants.REPORTS_DIR
    sample_logs_dir: str = constants.SAMPLE_LOG_DIR
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"

    def __post_init__(self) -> None:
        for directory in (self.log_dir, self.reports_dir, self.sample_logs_dir):
            Path(directory).mkdir(parents=True, exist_ok=True)


APP_CONFIG = AppConfig()
