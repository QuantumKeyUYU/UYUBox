# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

__all__ = [
    "DEFAULT_MEMORY_MAX",
    "DEFAULT_MEMORY_MIN",
    "DEFAULT_SALT_LENGTH",
    "DEFAULT_TIME_MAX",
    "derive_key",
    "derive_key_dynamic",
    "generate_salt",
]

import argon2.low_level as a2
import os
from typing import cast

from zilant_prime_core.crypto.g_new import G_new
from zilant_prime_core.utils.constants import DEFAULT_KEY_LENGTH, DEFAULT_SALT_LENGTH

DEFAULT_MEMORY_MIN = 2**15  # 32 MiB
DEFAULT_MEMORY_MAX = 2**17  # 128 MiB
DEFAULT_TIME_MAX = 5  # до 5 итераций


def generate_salt() -> bytes:
    return os.urandom(DEFAULT_SALT_LENGTH)


def derive_key(password: str | bytes, salt: bytes, key_length: int = DEFAULT_KEY_LENGTH) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not isinstance(password, (bytes, bytearray)):
        raise ValueError("Password must be bytes or string.")
    if not isinstance(salt, (bytes, bytearray)):
        raise ValueError("Salt must be bytes.")
    if not isinstance(key_length, int) or key_length <= 0:
        raise ValueError("Key length must be a positive integer.")
    return cast(
        bytes,
        a2.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=2,
            memory_cost=DEFAULT_MEMORY_MIN,
            parallelism=1,
            hash_len=key_length,
            type=a2.Type.ID,
        ),
    )


def derive_key_dynamic(
    password: str | bytes,
    salt: bytes,
    profile: float,
    key_length: int = DEFAULT_KEY_LENGTH,
    time_max: int = DEFAULT_TIME_MAX,
    mem_min: int = DEFAULT_MEMORY_MIN,
    mem_max: int = DEFAULT_MEMORY_MAX,
) -> bytes:
    if not isinstance(password, (str, bytes)):
        raise ValueError("Password must be str or bytes.")
    if not isinstance(salt, (bytes, bytearray)):
        raise ValueError("Salt must be bytes.")
    if len(salt) != DEFAULT_SALT_LENGTH:
        raise ValueError(f"Salt must be {DEFAULT_SALT_LENGTH} bytes long.")
    if not isinstance(profile, (int, float)):
        raise ValueError("Profile must be a number.")
    if not isinstance(key_length, int) or key_length <= 0:
        raise ValueError("Key length must be a positive integer.")
    if not isinstance(time_max, int) or time_max <= 0:
        raise ValueError("time_max must be a positive integer.")
    if not isinstance(mem_min, int) or mem_min <= 0:
        raise ValueError("mem_min must be a positive integer.")
    if not isinstance(mem_max, int) or mem_max < mem_min:
        raise ValueError("mem_max must be >= mem_min.")

    angle = abs(G_new(profile))  # ∈ [0, 1.5]
    norm = min(max(angle / 1.5, 0.0), 1.0)

    time_cost = 1 + int(norm * (time_max - 1))
    memory_cost = mem_min + int(norm * (mem_max - mem_min))

    if isinstance(password, str):
        password = password.encode("utf-8")

    return cast(
        bytes,
        a2.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=1,
            hash_len=key_length,
            type=a2.Type.ID,
        ),
    )
