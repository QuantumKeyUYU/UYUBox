# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import secrets

from zilant_prime_core.utils.secure_logging import SecureLogger


def test_secure_logger_hardening_sanity(tmp_path):
    # Проверяем, что разные уровни (DEBUG/INFO/WARN) корректно записываются и читаются
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "hardening.log")
    slog = SecureLogger(key=key, log_path=log_file)

    slog.log("First entry", "DEBUG")
    slog.log("Second entry", "INFO")
    slog.log("Third entry", "WARN")

    logs = slog.read_logs()

    # Проверяем наличие всех уровней и сообщений
    levels = [entry[0] for entry in logs]
    msgs = [entry[1] for entry in logs]

    assert set(["DEBUG", "INFO", "WARN"]).issubset(set(levels))
    assert "First entry" in msgs and "Second entry" in msgs and "Third entry" in msgs
