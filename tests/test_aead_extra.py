# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest
from cryptography.exceptions import InvalidTag

from zilant_prime_core.crypto import aead as aead_mod
from zilant_prime_core.crypto.aead import (
    DEFAULT_KEY_LENGTH,
    DEFAULT_NONCE_LENGTH,
    AEADError,
    AEADInvalidTagError,
    decrypt_aead,
    encrypt_aead,
    generate_nonce,
)


def test_encrypt_invalid_key_length():
    key = b"\x00" * (DEFAULT_KEY_LENGTH - 1)
    nonce = b"\x00" * DEFAULT_NONCE_LENGTH
    data = b"data"
    with pytest.raises(ValueError) as exc:
        encrypt_aead(key, nonce, data)
    assert f"Key must be {DEFAULT_KEY_LENGTH} bytes long." in str(exc.value)


def test_encrypt_invalid_nonce_length():
    key = b"\x00" * DEFAULT_KEY_LENGTH
    nonce = b"\x00" * (DEFAULT_NONCE_LENGTH - 1)
    data = b"data"
    with pytest.raises(ValueError) as exc:
        encrypt_aead(key, nonce, data)
    assert f"Nonce must be {DEFAULT_NONCE_LENGTH} bytes long." in str(exc.value)


def test_decrypt_invalid_key_length():
    key = b"\x00" * (DEFAULT_KEY_LENGTH - 1)
    nonce = b"\x00" * DEFAULT_NONCE_LENGTH
    ct_tag = b"\x00" * 16
    with pytest.raises(ValueError) as exc:
        decrypt_aead(key, nonce, ct_tag)
    assert f"Key must be {DEFAULT_KEY_LENGTH} bytes long." in str(exc.value)


def test_decrypt_invalid_nonce_length():
    key = b"\x00" * DEFAULT_KEY_LENGTH
    nonce = b"\x00" * (DEFAULT_NONCE_LENGTH - 1)
    ct_tag = b"\x00" * 16
    with pytest.raises(ValueError) as exc:
        decrypt_aead(key, nonce, ct_tag)
    assert f"Nonce must be {DEFAULT_NONCE_LENGTH} bytes long." in str(exc.value)


def test_decrypt_ct_too_short():
    key = b"\x00" * DEFAULT_KEY_LENGTH
    nonce = b"\x00" * DEFAULT_NONCE_LENGTH
    ct_tag = b"\x00" * 15  # должно быть хотя бы 16 байт
    with pytest.raises(ValueError) as exc:
        decrypt_aead(key, nonce, ct_tag)
    assert "Ciphertext is too short to contain the authentication tag." in str(exc.value)


def test_decrypt_invalid_tag(monkeypatch):
    # Подменяем ChaCha20Poly1305, чтобы decrypt бросал InvalidTag
    class DummyCH:
        def __init__(self, key):
            pass

        def decrypt(self, nonce, ct, aad=None):
            raise InvalidTag("bad tag")

    monkeypatch.setattr(aead_mod, "ChaCha20Poly1305", DummyCH)

    key = b"\x00" * DEFAULT_KEY_LENGTH
    nonce = b"\x00" * DEFAULT_NONCE_LENGTH
    ct_tag = b"\x00" * 16
    with pytest.raises(AEADInvalidTagError) as exc:
        decrypt_aead(key, nonce, ct_tag)
    assert "Invalid authentication tag." in str(exc.value)


def test_decrypt_other_exception(monkeypatch):
    # Подменяем ChaCha20Poly1305, чтобы decrypt бросал произвольное исключение
    class DummyCH:
        def __init__(self, key):
            pass

        def decrypt(self, nonce, ct, aad=None):
            raise RuntimeError("unexpected")

    monkeypatch.setattr(aead_mod, "ChaCha20Poly1305", DummyCH)

    key = b"\x00" * DEFAULT_KEY_LENGTH
    nonce = b"\x00" * DEFAULT_NONCE_LENGTH
    ct_tag = b"\x00" * 16
    with pytest.raises(AEADError) as exc:
        decrypt_aead(key, nonce, ct_tag)
    assert "unexpected" in str(exc.value)


def test_generate_nonce_length_and_randomness():
    n1 = generate_nonce()
    n2 = generate_nonce()
    assert isinstance(n1, bytes)
    assert len(n1) == DEFAULT_NONCE_LENGTH
    # маловероятно, что два случайных nonce совпадут
    assert n1 != n2
