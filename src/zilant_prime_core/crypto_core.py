# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Branchless cryptographic primitives."""

from __future__ import annotations

import argon2.low_level as a2
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import cast

__all__ = [
    "encrypt_chacha20_poly1305",
    "decrypt_chacha20_poly1305",
    "derive_key_argon2id",
    "derive_key_double",
]


def encrypt_chacha20_poly1305(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Encrypt *data* with ChaCha20-Poly1305."""
    ch = ChaCha20Poly1305(bytes(key))
    return cast(bytes, ch.encrypt(bytes(nonce), data, None))


def decrypt_chacha20_poly1305(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Decrypt ChaCha20-Poly1305 payload."""
    ch = ChaCha20Poly1305(bytes(key))
    return cast(bytes, ch.decrypt(bytes(nonce), data, None))


def derive_key_argon2id(
    password: bytes,
    salt: bytes,
    mem_cost: int = 512 * 1024,
    time_cost: int = 4,
) -> bytes:
    """Derive key via Argon2id."""
    pwd = bytes(password)
    sl = bytes(salt)
    return cast(
        bytes,
        a2.hash_secret_raw(
            secret=pwd,
            salt=sl,
            time_cost=time_cost,
            memory_cost=mem_cost,
            parallelism=1,
            hash_len=32,
            type=a2.Type.ID,
        ),
    )


def derive_key_double(password: bytes, salt: bytes) -> bytes:
    """Branchless double Argon2id derivation."""
    real = derive_key_argon2id(password, salt)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=len(salt),
        salt=salt,
        info=b"decoy",
    )
    alt_salt = kdf.derive(password)
    decoy = derive_key_argon2id(password, alt_salt)
    return bytes(a ^ b for a, b in zip(real, decoy, strict=False))
