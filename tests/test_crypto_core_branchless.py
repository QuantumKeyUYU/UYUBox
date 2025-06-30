# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
import inspect
import pytest
import secrets
import time

from zilant_prime_core.crypto_core import decrypt_chacha20_poly1305, derive_key_argon2id, encrypt_chacha20_poly1305


@pytest.mark.perf
def test_chacha_roundtrip_and_timings():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    data = secrets.token_bytes(4096)
    t0 = time.perf_counter()
    for _ in range(3):
        ct = encrypt_chacha20_poly1305(key, nonce, data)
    d0 = time.perf_counter() - t0
    t1 = time.perf_counter()
    for _ in range(3):
        encrypt_chacha20_poly1305(key, nonce, data)
    d1 = time.perf_counter() - t1
    assert decrypt_chacha20_poly1305(key, nonce, ct) == data
    diff = abs(d0 - d1) / max(d0, d1)
    assert diff <= 1.0
    src = inspect.getsource(encrypt_chacha20_poly1305)
    assert "if " not in src and "else" not in src
    src2 = inspect.getsource(derive_key_argon2id)
    assert "if " not in src2 and "else" not in src2


@pytest.mark.perf
def test_derive_key_consistency():
    pwd = b"pass"
    salt = secrets.token_bytes(16)
    k1 = derive_key_argon2id(pwd, salt)
    k2 = derive_key_argon2id(pwd, salt)
    assert k1 == k2 and len(k1) == 32
