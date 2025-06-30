# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import base64
import json
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

from zilant_prime_core.utils.secure_logging import SecureLogger


def test_secure_logger_zeroize(tmp_path):
    key = secrets.token_bytes(32)
    log_path = tmp_path / "sec.log"
    slog = SecureLogger(key=key, log_path=str(log_path))
    for i in range(3):
        slog.log(f"m{i}", "L{i}")

    records = []
    aes = AESGCM(key)
    for line in log_path.read_bytes().splitlines():
        nonce_b64, ct_b64 = line.split(b"|")
        pt = aes.decrypt(base64.b64decode(nonce_b64), base64.b64decode(ct_b64), None)
        records.append(json.loads(pt.decode()))
    assert len(records) == 3

    slog.zeroize()
    assert not log_path.exists()
    enc_path = Path(str(log_path) + ".enc")
    assert enc_path.exists()


def test_zeroize_missing(tmp_path):
    from zilant_prime_core.utils.secure_logging import SecureLogger

    slog = SecureLogger(key=b"0" * 32, log_path=str(tmp_path / "log"))
    # no file yet
    slog.zeroize()  # just ensures no error when file absent
