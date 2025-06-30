# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest

from aead import decrypt, encrypt


def test_encrypt_invalid_key_type():
    with pytest.raises(TypeError):
        encrypt("notbytes", b"plaintext")


def test_encrypt_invalid_key_length():
    with pytest.raises(ValueError):
        encrypt(b"short", b"plaintext")


def test_decrypt_invalid_key():
    with pytest.raises(ValueError):
        decrypt(b"short", b"\x00" * 12, b"cipher")


def test_decrypt_invalid_nonce_length():
    key = os.urandom(32)
    with pytest.raises(ValueError):
        decrypt(key, b"short", b"cipher")


def test_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    plaintext = b"message"
    nonce, ct = encrypt(key, plaintext, aad=b"aad")
    assert decrypt(key, nonce, ct, aad=b"aad") == plaintext
