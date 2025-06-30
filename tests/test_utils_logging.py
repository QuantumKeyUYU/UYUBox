# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import logging

import zilant_prime_core.utils.logging as zl


def test_get_logger_basic(monkeypatch):
    logger = logging.getLogger("test_logger_basic")
    logger.handlers.clear()
    log = zl.get_logger("test_logger_basic", secure=False)
    assert isinstance(log, logging.Logger)
    assert log.name == "test_logger_basic"


def test_get_logger_env(monkeypatch):
    monkeypatch.setenv("ZILANT_SECURE_LOG", "1")
    logger = zl.get_logger("test_logger_env", secure=None)
    assert logger


def test_get_logger_secure_true(monkeypatch):
    logger = zl.get_logger("test_logger_true", secure=True)
    assert logger


def test_get_logger_secure_false(monkeypatch):
    logger = zl.get_logger("test_logger_false", secure=False)
    assert logger


def test_get_file_logger_basic(monkeypatch, tmp_path):
    log_path = tmp_path / "myfile.log"
    logger = zl.get_file_logger("test_file_logger_basic", file_path=str(log_path), secure=False)
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_file_logger_basic"


def test_get_file_logger_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ZILANT_SECURE_LOG", "1")
    log_path = tmp_path / "envfile.log"
    logger = zl.get_file_logger("test_file_logger_env", file_path=str(log_path), secure=None)
    assert logger


def test_get_file_logger_secure_true(monkeypatch, tmp_path):
    log_path = tmp_path / "securefile.log"
    logger = zl.get_file_logger("test_file_logger_true", file_path=str(log_path), secure=True)
    assert logger


def test_get_file_logger_secure_false(monkeypatch, tmp_path):
    log_path = tmp_path / "securefile2.log"
    logger = zl.get_file_logger("test_file_logger_false", file_path=str(log_path), secure=False)
    assert logger


def test_get_file_logger_handlers(tmp_path):
    logger = logging.getLogger("test_file_logger_handlers")
    logger.handlers.clear()
    log_path = tmp_path / "handlerfile.log"
    zl.get_file_logger("test_file_logger_handlers", file_path=str(log_path), secure=False)
    assert logger.handlers
