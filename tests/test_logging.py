# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from logging.handlers import RotatingFileHandler
from pathlib import Path

from utils.logging import get_logger


def test_get_logger_singleton(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    logger1 = get_logger("foo")
    logger2 = get_logger("foo")
    assert logger1 is logger2
    assert any(isinstance(h, RotatingFileHandler) for h in logger1.handlers)


def test_logger_writes_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    logger = get_logger("bar")
    logger.info("hello world")
    for h in logger.handlers:
        h.flush()
    log_file = Path(".zilant_log")
    assert log_file.exists()
    text = log_file.read_text()
    assert "hello world" in text
