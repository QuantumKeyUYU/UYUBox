# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import os
import pytest
import secrets

import zilant_prime_core.utils.secure_logging as secure_logging


def test_secure_logger_bad_key(tmp_path):
    # Если ключ неверной длины, __init__ кидает ValueError
    with pytest.raises(ValueError):
        secure_logging.SecureLogger(key=b"short", log_path=str(tmp_path / "x.log"))


def test_get_secure_logger_singleton_and_env(tmp_path, monkeypatch):
    # Сброс singleton
    secure_logging._default = None

    # 1) Если нет ключа и нет env → генерируется новый ключ в ZILANT_LOG_KEY
    monkeypatch.delenv("ZILANT_LOG_KEY", raising=False)
    log_path = str(tmp_path / "singleton.log")
    slog1 = secure_logging.get_secure_logger(log_path=log_path)
    assert isinstance(slog1, secure_logging.SecureLogger)
    assert "ZILANT_LOG_KEY" in os.environ

    # 2) Повторный вызов — возвращает тот же объект (singleton)
    slog2 = secure_logging.get_secure_logger(log_path=log_path)
    assert slog1 is slog2

    # 3) Если передать свой key после того, как singleton уже создан,
    #    всё равно вернётся существующий singleton
    key = secrets.token_bytes(32)
    another_log_path = str(tmp_path / "another.log")
    slog3 = secure_logging.get_secure_logger(key=key, log_path=another_log_path)
    assert slog3 is slog1

    # 4) Работа с singleton (ключ из env) — записываем и читаем одну запись
    slog1.log("TOP_SECRET", "SECRET_MESSAGE")
    entries = slog1.read_logs()
    # Проверяем, что (уровень, сообщение) правильно лежит в entries:
    assert ("SECRET_MESSAGE", "TOP_SECRET") in entries
