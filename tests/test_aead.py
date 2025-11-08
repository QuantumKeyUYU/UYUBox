"""Tests for AEAD helper utilities."""
from __future__ import annotations

from hashlib import pbkdf2_hmac

DEFAULT_KEY_LENGTH = 32


# Helper to derive a test key (not real KDF, just for tests)
def generate_test_key(password: bytes, salt: bytes) -> bytes:
    """Derive a deterministic test key using a robust KDF."""

    return pbkdf2_hmac(
        "sha256",
        password,
        salt,
        100_000,
        dklen=DEFAULT_KEY_LENGTH,
    )


def test_generate_test_key_length():
    key = generate_test_key(b"password", b"salt")
    assert len(key) == DEFAULT_KEY_LENGTH


def test_generate_test_key_salt_variation():
    key1 = generate_test_key(b"password", b"salt1")
    key2 = generate_test_key(b"password", b"salt2")
    assert key1 != key2


def test_generate_test_key_password_variation():
    key1 = generate_test_key(b"password1", b"salt")
    key2 = generate_test_key(b"password2", b"salt")
    assert key1 != key2
