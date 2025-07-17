"""Very small stand-in for AESGCM and ChaCha20Poly1305."""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from ... import exceptions


class AESGCM:
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) not in (16, 24, 32):
            raise ValueError("AESGCM key must be 16, 24, or 32 bytes")
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
        stream = hashlib.sha256(self._key + nonce).digest()
        out = bytes(b ^ stream[i % len(stream)] for i, b in enumerate(data))
        tag = hmac.new(self._key, nonce + out + aad, hashlib.sha256).digest()[:16]
        return out + tag

    def decrypt(self, nonce: bytes, data: bytes, aad: Optional[bytes]) -> bytes:
        if len(data) < 16:
            raise exceptions.InvalidTag("ciphertext too short")
        ct, tag = data[:-16], data[-16:]
        aad = aad or b""
        calc = hmac.new(self._key, nonce + ct + aad, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, calc):
            raise exceptions.InvalidTag("authentication failed")
        stream = hashlib.sha256(self._key + nonce).digest()
        return bytes(b ^ stream[i % len(stream)] for i, b in enumerate(ct))


class ChaCha20Poly1305(AESGCM):
    """Alias of AESGCM with same lightweight behaviour."""
