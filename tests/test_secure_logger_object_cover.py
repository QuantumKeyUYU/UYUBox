# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import secrets

from zilant_prime_core.utils.secure_logging import SecureLogger


def test_secure_logger_object_cover(tmp_path):
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "objcover.log")
    slog = SecureLogger(key=key, log_path=log_file)

    slog.log("Cover test", "COVER", extra=123)
    entries = slog.read_logs()

    # Должны получить как минимум одну кортежную запись уровня и сообщения
    assert isinstance(entries, list)
    assert entries[0][0] == "COVER"
    assert entries[0][1] == "Cover test"
