"""Rotating file logging so guard.py can run for weeks without an
unbounded log file -- there was no log file at all before this, just
raw print() to whatever redirected stdout, which is exactly how you get
a multi-gigabyte log after a month of 5-second ticks.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file
BACKUP_COUNT = 5              # keep 5 old files -- 60 MB total ceiling, not unbounded


def setup_logging(log_path: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("server-guard")
    logger.setLevel(level)
    logger.handlers.clear()  # avoid duplicate handlers if called more than once in a process

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    file_handler = RotatingFileHandler(log_path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT,
                                        encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
