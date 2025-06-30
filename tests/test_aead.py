# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import builtins
import hashlib

# tests/test_aead.py
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


def debug_print(*args, **kwargs):
    """A simple print function that might work better in test environments."""
    builtins.print("DEBUG:", *args, **kwargs)


# Helper to derive a test key (not real KDF, just for tests)
def generate_test_key(password: bytes, salt: bytes) -> bytes:
    h = hashlib.sha256(password + salt).digest()
    return h[:DEFAULT_KEY_LENGTH]


def test_encrypt_decrypt_success():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    payload = b"This is the secret message."
    aad = b"additional authenticated data"

    ct = encrypt_aead(key, nonce, payload, aad)
    assert isinstance(ct, bytes)
    assert len(ct) == len(payload) + 16

    pt = decrypt_aead(key, nonce, ct, aad)
    assert pt == payload


def test_encrypt_decrypt_empty_payload():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    ct = encrypt_aead(key, nonce, b"", b"aad")
    assert len(ct) == 16
    assert decrypt_aead(key, nonce, ct, b"aad") == b""


def test_encrypt_decrypt_empty_aad():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    payload = b"Payload"
    ct = encrypt_aead(key, nonce, payload, b"")
    assert len(ct) == len(payload) + 16
    assert decrypt_aead(key, nonce, ct, b"") == payload


def test_decrypt_invalid_key():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    bad = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    ct = encrypt_aead(key, nonce, b"data", b"aad")
    with pytest.raises(AEADInvalidTagError):
        decrypt_aead(bad, nonce, ct, b"aad")


def test_decrypt_invalid_nonce():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    ct = encrypt_aead(key, nonce, b"data", b"aad")
    with pytest.raises(AEADInvalidTagError):
        decrypt_aead(key, generate_nonce(), ct, b"aad")


def test_decrypt_tampered_ciphertext():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    ct = encrypt_aead(key, nonce, b"secret", b"aad")
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    with pytest.raises(AEADInvalidTagError):
        decrypt_aead(key, nonce, bytes(tampered), b"aad")


def test_decrypt_tampered_tag():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    ct = encrypt_aead(key, nonce, b"secret", b"aad")
    tampered = bytearray(ct)
    tampered[-16] ^= 0xFF
    with pytest.raises(AEADInvalidTagError):
        decrypt_aead(key, nonce, bytes(tampered), b"aad")


def test_decrypt_tampered_aad():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    ct = encrypt_aead(key, nonce, b"secret", b"aad")
    with pytest.raises(AEADInvalidTagError):
        decrypt_aead(key, nonce, ct, b"wrong")


def test_encrypt_aead_invalid_input_lengths():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    with pytest.raises(ValueError, match=f"Key must be {DEFAULT_KEY_LENGTH} bytes long."):
        encrypt_aead(key[:-1], nonce, b"d", b"a")
    with pytest.raises(ValueError, match=f"Nonce must be {DEFAULT_NONCE_LENGTH} bytes long."):
        encrypt_aead(key, nonce[:-1], b"d", b"a")


def test_decrypt_aead_invalid_input_lengths():
    key = os.urandom(DEFAULT_KEY_LENGTH)
    nonce = generate_nonce()
    ct = encrypt_aead(key, nonce, b"data", b"aad")
    with pytest.raises(ValueError, match=f"Key must be {DEFAULT_KEY_LENGTH} bytes long."):
        decrypt_aead(key[:-1], nonce, ct, b"aad")
    with pytest.raises(ValueError, match=f"Nonce must be {DEFAULT_NONCE_LENGTH} bytes long."):
        decrypt_aead(key, nonce[:-1], ct, b"aad")
    with pytest.raises(ValueError, match="Ciphertext is too short to contain the authentication tag."):
        decrypt_aead(key, nonce, b"short", b"aad")
