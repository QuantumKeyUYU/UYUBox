# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

__all__ = ["get_logger"]


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger writing to `.zilant_log`."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    log_path = Path(".zilant_log")
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
