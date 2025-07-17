import os
import hashlib


class X25519PrivateKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    @classmethod
    def generate(cls) -> "X25519PrivateKey":
        return cls(os.urandom(32))

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "X25519PrivateKey":
        return cls(data)

    def public_key(self) -> "X25519PublicKey":
        return X25519PublicKey(self._key)

    def exchange(self, peer: "X25519PublicKey") -> bytes:
        xored = bytes(a ^ b for a, b in zip(self._key, peer._key, strict=True))
        return hashlib.sha256(xored).digest()

    def private_bytes(self, *args, **kwargs) -> bytes:
        return self._key


class X25519PublicKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "X25519PublicKey":
        return cls(data)

    def public_bytes(self, *args, **kwargs) -> bytes:
        return self._key
