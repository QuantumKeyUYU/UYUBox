# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest

from src.aead import decrypt, decrypt_chacha20_poly1305, encrypt, encrypt_chacha20_poly1305


def test_encrypt_invalid_key_type():
    nonce = os.urandom(12)
    with pytest.raises(TypeError):
        encrypt_chacha20_poly1305("notbytes", nonce, b"x", b"y")


def test_encrypt_invalid_nonce_type():
    key = os.urandom(32)
    with pytest.raises(TypeError):
        encrypt_chacha20_poly1305(key, "notbytes", b"x", b"y")


def test_encrypt_invalid_payload_type():
    key = os.urandom(32)
    nonce = os.urandom(12)
    with pytest.raises(TypeError):
        encrypt_chacha20_poly1305(key, nonce, "notbytes", b"y")


def test_encrypt_invalid_aad_type():
    key = os.urandom(32)
    nonce = os.urandom(12)
    with pytest.raises(TypeError):
        encrypt_chacha20_poly1305(key, nonce, b"x", 123)


def test_decrypt_invalid_tag_type():
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct = b"x" * 30
    with pytest.raises(TypeError):
        decrypt_chacha20_poly1305(key, nonce, ct, "notbytes", b"")


def test_decrypt_invalid_aad_type():
    key = os.urandom(32)
    nonce = os.urandom(12)
    ct = b"x" * 30
    tag = b"x" * 16
    with pytest.raises(TypeError):
        decrypt_chacha20_poly1305(key, nonce, ct, tag, 123)


def test_encrypt_api_wrong_key_type():
    with pytest.raises(TypeError):
        encrypt("notbytes", b"x")


def test_encrypt_api_wrong_plaintext_type():
    key = os.urandom(32)
    with pytest.raises(TypeError):
        encrypt(key, "notbytes")


def test_encrypt_api_wrong_aad_type():
    key = os.urandom(32)
    with pytest.raises(TypeError):
        encrypt(key, b"x", aad=123)


def test_decrypt_api_wrong_key_type():
    with pytest.raises(ValueError):
        decrypt("notbytes", b"x" * 12, b"x")


def test_decrypt_api_wrong_key_len():
    key = os.urandom(16)
    with pytest.raises(ValueError):
        decrypt(key, b"x" * 12, b"x")


def test_decrypt_api_wrong_nonce_type():
    key = os.urandom(32)
    with pytest.raises(ValueError):
        decrypt(key, "notbytes", b"x")


def test_decrypt_api_wrong_nonce_len():
    key = os.urandom(32)
    nonce = os.urandom(8)
    with pytest.raises(ValueError):
        decrypt(key, nonce, b"x")


def test_decrypt_api_wrong_ciphertext_type():
    key = os.urandom(32)
    nonce = os.urandom(12)
    with pytest.raises(TypeError):
        decrypt(key, nonce, "notbytes")


def test_decrypt_api_wrong_aad_type():
    key = os.urandom(32)
    nonce = os.urandom(12)
    with pytest.raises(TypeError):
        decrypt(key, nonce, b"x", aad=123)
