"""Fallback ChaCha20Poly1305 implementation used when cryptography is missing."""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional


class InvalidTag(Exception):
    """Raised when authentication fails."""


class ChaCha20Poly1305:
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self._key = bytes(key)

    def encrypt(self, nonce: bytes, data: bytes, aad: Optional[bytes]) -> bytes:
        if not isinstance(nonce, (bytes, bytearray)):
            raise TypeError("nonce must be bytes")
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        if aad is not None and not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes")
        aad = aad or b""
        stream = hashlib.blake2b(self._key + nonce, digest_size=len(data)).digest()
        ct = bytes(b ^ stream[i] for i, b in enumerate(data))
        tag = hmac.new(self._key, nonce + ct + aad, hashlib.sha256).digest()[:16]
        return ct + tag

    def decrypt(self, nonce: bytes, data: bytes, aad: Optional[bytes]) -> bytes:
        if len(data) < 16:
            raise InvalidTag("ciphertext too short")
        ct, tag = data[:-16], data[-16:]
        aad = aad or b""
        calc = hmac.new(self._key, nonce + ct + aad, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, calc):
            raise InvalidTag("authentication failed")
        stream = hashlib.blake2b(self._key + nonce, digest_size=len(ct)).digest()
        return bytes(b ^ stream[i] for i, b in enumerate(ct))
