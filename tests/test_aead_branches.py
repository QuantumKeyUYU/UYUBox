# tests/test_aead_branches.py

# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import os
import pytest

from zilant_prime_core.crypto.aead import (
    DEFAULT_KEY_LENGTH,
    DEFAULT_NONCE_LENGTH,
    AEADInvalidTagError,
    decrypt_aead,
    encrypt_aead,
    generate_nonce,
)


def test_generate_nonce_default_length():
    nonce = generate_nonce()
    assert isinstance(nonce, bytes)
    assert len(nonce) == DEFAULT_NONCE_LENGTH


@pytest.mark.parametrize(
    "bad_key",
    [
        b"",  # слишком короткий
        os.urandom(DEFAULT_KEY_LENGTH + 1),  # слишком длинный
        "not-bytes",  # не bytes
    ],
)
def test_encrypt_aead_invalid_key(bad_key):
    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    with pytest.raises(ValueError):
        encrypt_aead(bad_key, nonce, b"data")


@pytest.mark.parametrize(
    "bad_nonce",
    [
        b"",
        os.urandom(DEFAULT_NONCE_LENGTH + 1),
        "not-bytes",
    ],
)
def test_encrypt_aead_invalid_nonce(bad_nonce):
    key = os.urandom(DEFAULT_KEY_LENGTH)
    with pytest.raises(ValueError):
        encrypt_aead(key, bad_nonce, b"data")


def test_decrypt_aead_invalid_key():
    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    fake_ct = os.urandom(DEFAULT_NONCE_LENGTH + 16)
    with pytest.raises(ValueError):
        decrypt_aead("badkey", nonce, fake_ct)


def test_decrypt_aead_invalid_nonce():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    fake_ct = os.urandom(DEFAULT_NONCE_LENGTH + 16)
    with pytest.raises(ValueError):
        decrypt_aead(key, b"badnonce", fake_ct)


def test_decrypt_aead_too_short_ciphertext():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    with pytest.raises(ValueError):
        # менее 16 байт (размер тега) — сразу ValueError
        decrypt_aead(key, nonce, b"\x00" * 8)


def test_decrypt_aead_invalid_tag_raises_AEADInvalidTagError():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    bad_ct = os.urandom(32)  # валидная длина, но случайное содержимое → InvalidTag
    with pytest.raises(AEADInvalidTagError):
        decrypt_aead(key, nonce, bad_ct)


def test_encrypt_decrypt_roundtrip():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    data = b"hello"
    ct = encrypt_aead(key, nonce, data, aad=b"aad")
    pt = decrypt_aead(key, nonce, ct, aad=b"aad")
    assert pt == data
