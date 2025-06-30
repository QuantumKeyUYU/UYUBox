# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import os
import pytest
import secrets

from zilant_prime_core.utils.secure_logging import SecureLogger, get_secure_logger


def test_secure_logger_accepts_raw_bytes_key(tmp_path):
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "s.log")
    slog = SecureLogger(key=key, log_path=log_file)
    slog.log("payload", "LEVEL")
    entries = slog.read_logs()
    assert entries == [("LEVEL", "payload")]


def test_secure_logger_invalid_key_raises():
    with pytest.raises(ValueError):
        SecureLogger(key=b"short", log_path="x.log")


def test_get_secure_logger_singleton(monkeypatch, tmp_path):
    # Сбросим singleton
    import zilant_prime_core.utils.secure_logging as sl

    sl._default = None

    os.environ.pop("ZILANT_LOG_KEY", None)
    path = str(tmp_path / "one.log")
    slog1 = get_secure_logger(log_path=path)
    slog2 = get_secure_logger(log_path=path)
    assert slog1 is slog2


def test_secure_logger_fields_update(tmp_path):
    # Проверяет покрытие работы с **fields
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "fields.log")
    slog = SecureLogger(key=key, log_path=log_file)
    slog.log("test", "L1", foo="bar", id=7)
    entries = slog.read_logs()
    # Должны получить (level, msg) и затем (level, msg, {...})
    assert ("L1", "test") in entries
    assert any(len(item) == 3 for item in entries)


def test_secure_logger_read_logs_no_file(tmp_path):
    # Если файл отсутствует, возвращает пустой список
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "no_such_file.log")
    slog = SecureLogger(key=key, log_path=log_file)
    assert slog.read_logs() == []


def test_secure_logger_handles_corrupt_log(tmp_path):
    # Повреждённая строка пропускается, не ломает всё
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "corrupt.log")
    slog = SecureLogger(key=key, log_path=log_file)
    with open(log_file, "ab") as f:
        f.write(b"not|a|valid|log\n")
    slog.log("hello", "INFO")
    entries = slog.read_logs()
    assert ("INFO", "hello") in entries
