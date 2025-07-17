from __future__ import annotations
import base64
import hashlib
import hmac


from . import exceptions, low_level

__all__ = ["PasswordHasher", "exceptions", "low_level"]


class PasswordHasher:
    """Very small stand-in for argon2-cffi's PasswordHasher."""

    def __init__(
        self,
        time_cost: int = 2,
        memory_cost: int = 64 * 1024,
        parallelism: int = 2,
        hash_len: int = 32,
    ) -> None:
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self._salt = b"argon2-stub"

    def hash(self, password: str) -> str:
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            self._salt,
            self.time_cost * 5000,
        )
        return base64.b64encode(dk[: self.hash_len]).decode()

    def verify(self, hash_: str, password: str) -> bool:
        expected = self.hash(password)
        if not hmac.compare_digest(hash_, expected):
            raise exceptions.VerifyMismatchError()
        return True
