# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import base64
import secrets

from zilant_prime_core.utils.secure_logging import SecureLogger, get_decryption_attempts


def test_decryption_attempt_counter(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("ZILANT_LOG_KEY", base64.urlsafe_b64encode(key).decode())
    log_file = tmp_path / "s.log"
    slog = SecureLogger(log_path=str(log_file))
    slog.log("hi")
    before = get_decryption_attempts()
    slog.read_logs()
    assert get_decryption_attempts() == before + 1
