from __future__ import annotations

"""Utility encryption helpers."""

import os
from typing import List

from streaming_aead import decrypt_chunk, encrypt_chunk


def onion_encrypt(plaintext: bytes, keys: List[bytes]) -> bytes:
    """Apply multiple encryption layers using XChaCha20-Poly1305."""
    data = plaintext
    for key in keys:
        nonce = os.urandom(24)
        data = nonce + encrypt_chunk(key, nonce, data)
    return data


def onion_decrypt(ciphertext: bytes, keys: List[bytes]) -> bytes:
    """Remove layers added by :func:`onion_encrypt`."""
    data = ciphertext
    for key in reversed(keys):
        nonce, payload = data[:24], data[24:]
        data = decrypt_chunk(key, nonce, payload)
    return data
