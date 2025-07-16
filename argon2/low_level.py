from __future__ import annotations
import hashlib
from typing import Any


class Type:
    I = 1  # noqa: E741 - match argon2 API
    ID = 2


def hash_secret_raw(
    secret: bytes,
    salt: bytes,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int,
    type: Any,
) -> bytes:
    """Derive a key using a simplified PBKDF2 stand-in."""
    rounds = max(1, time_cost) * 5000
    return hashlib.pbkdf2_hmac("sha256", secret, salt, rounds, dklen=hash_len)
