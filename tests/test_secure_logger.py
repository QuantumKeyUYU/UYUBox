# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zilant_prime_core.utils.secure_logging import SecureLogger


def test_secure_logger_write_and_zeroize(tmp_path):
    key = secrets.token_bytes(32)
    log_dir = tmp_path / "logs"
    log_path = log_dir / "zilant.log"
    slog = SecureLogger(key=key, log_path=str(log_path))
    slog.log("a")
    slog.log("b")
    slog.log("c")
    lines = log_path.read_bytes().splitlines()
    assert len(lines) == 3
    slog.zeroize()
    enc = log_path.with_suffix(".log.enc")
    assert not log_path.exists() and enc.exists()
    with open(enc, "rb") as f:
        nonce_b64, ct_b64 = f.read().split(b"|")
    AESGCM(key).decrypt(base64.b64decode(nonce_b64), base64.b64decode(ct_b64), None)
