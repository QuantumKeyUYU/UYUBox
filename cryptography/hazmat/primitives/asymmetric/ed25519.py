from __future__ import annotations
import os
import hashlib
import hmac


class Ed25519PrivateKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    @classmethod
    def generate(cls) -> "Ed25519PrivateKey":
        return cls(os.urandom(32))

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "Ed25519PrivateKey":
        if len(data) != 32:
            raise ValueError("private key must be 32 bytes")
        return cls(data)

    def public_key(self) -> "Ed25519PublicKey":
        return Ed25519PublicKey(self._key)

    def sign(self, data: bytes) -> bytes:
        digest = hmac.new(self._key, data, hashlib.sha256).digest()
        # Expand to 64 bytes to mimic real Ed25519 signature length
        return digest + digest

    def private_bytes(self, *, encoding, format, encryption_algorithm) -> bytes:
        return self._key


class Ed25519PublicKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "Ed25519PublicKey":
        if len(data) != 32:
            raise ValueError("public key must be 32 bytes")
        return cls(data)

    def public_bytes(self, *, encoding, format) -> bytes:
        return self._key

    def verify(self, signature: bytes, data: bytes) -> None:
        expected = hmac.new(self._key, data, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature verification failed")
