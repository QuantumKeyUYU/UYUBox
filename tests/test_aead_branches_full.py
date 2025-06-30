# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
import secrets

from src.aead import AEADInvalidTagError, decrypt_chacha20_poly1305, encrypt_chacha20_poly1305


def test_encrypt_invalid_key_length():
    key = secrets.token_bytes(15)  # wrong length
    nonce = secrets.token_bytes(12)
    payload = b"hi"
    aad = b""
    with pytest.raises(ValueError):
        encrypt_chacha20_poly1305(key, nonce, payload, aad)


def test_encrypt_invalid_nonce_length():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(8)  # wrong length
    payload = b"hi"
    aad = b""
    with pytest.raises(ValueError):
        encrypt_chacha20_poly1305(key, nonce, payload, aad)


def test_decrypt_invalid_key_length():
    key = secrets.token_bytes(15)
    nonce = secrets.token_bytes(12)
    ct = secrets.token_bytes(30)
    aad = b""
    tag = secrets.token_bytes(16)
    with pytest.raises(ValueError):
        decrypt_chacha20_poly1305(key, nonce, ct, tag, aad)


def test_decrypt_invalid_nonce_length():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(8)
    ct = secrets.token_bytes(30)
    aad = b""
    tag = secrets.token_bytes(16)
    with pytest.raises(ValueError):
        decrypt_chacha20_poly1305(key, nonce, ct, tag, aad)


def test_decrypt_invalid_tag_length():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    ct = secrets.token_bytes(30)
    aad = b""
    tag = secrets.token_bytes(10)
    with pytest.raises(ValueError):
        decrypt_chacha20_poly1305(key, nonce, ct, tag, aad)


def test_decrypt_invalid_type():
    with pytest.raises(TypeError):
        decrypt_chacha20_poly1305("notbytes", b"123456789012", b"ct", b"tagtagtagtagtagg", b"aad")


def test_decrypt_invalid_tag():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    payload = b"test"
    aad = b"aad"
    ct, tag = encrypt_chacha20_poly1305(key, nonce, payload, aad)
    bad_tag = b"\x00" * 16
    with pytest.raises(AEADInvalidTagError):
        decrypt_chacha20_poly1305(key, nonce, ct, bad_tag, aad)


def test_decrypt_invalid_ciphertext_type():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    tag = secrets.token_bytes(16)
    with pytest.raises(TypeError):
        decrypt_chacha20_poly1305(key, nonce, 12345, tag, b"aad")


def test_encrypt_invalid_aad_type():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    payload = b"hi"
    with pytest.raises(TypeError):
        encrypt_chacha20_poly1305(key, nonce, payload, 12345)
