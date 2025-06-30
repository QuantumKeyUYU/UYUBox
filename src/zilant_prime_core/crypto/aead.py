# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

__all__ = [
    "AEADError",
    "AEADInvalidTagError",
    "DEFAULT_KEY_LENGTH",
    "DEFAULT_NONCE_LENGTH",
    "decrypt_aead",
    "encrypt_aead",
    "generate_nonce",
]

import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import cast

from zilant_prime_core.utils.constants import DEFAULT_KEY_LENGTH, DEFAULT_NONCE_LENGTH

DEFAULT_KEY_LENGTH = DEFAULT_KEY_LENGTH
DEFAULT_NONCE_LENGTH = DEFAULT_NONCE_LENGTH


class AEADError(Exception):
    """Общая ошибка AEAD."""


class AEADInvalidTagError(AEADError):
    """Неверная метка аутентификации."""


def generate_nonce() -> bytes:
    return os.urandom(DEFAULT_NONCE_LENGTH)


def encrypt_aead(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != DEFAULT_KEY_LENGTH:
        raise ValueError(f"Key must be {DEFAULT_KEY_LENGTH} bytes long.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != DEFAULT_NONCE_LENGTH:
        raise ValueError(f"Nonce must be {DEFAULT_NONCE_LENGTH} bytes long.")
    ch = ChaCha20Poly1305(key)
    return cast(bytes, ch.encrypt(nonce, data, aad))


def decrypt_aead(key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes = b"") -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != DEFAULT_KEY_LENGTH:
        raise ValueError(f"Key must be {DEFAULT_KEY_LENGTH} bytes long.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != DEFAULT_NONCE_LENGTH:
        raise ValueError(f"Nonce must be {DEFAULT_NONCE_LENGTH} bytes long.")
    if not isinstance(ct_tag, (bytes, bytearray)) or len(ct_tag) < 16:
        raise ValueError("Ciphertext is too short to contain the authentication tag.")
    ch = ChaCha20Poly1305(key)
    try:
        return cast(bytes, ch.decrypt(nonce, ct_tag, aad))
    except InvalidTag:
        raise AEADInvalidTagError("Invalid authentication tag.")
    except Exception as e:
        raise AEADError(str(e))
