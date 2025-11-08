"""Adaptive Argon2id profile selection."""
from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from typing import Literal

from argon2.low_level import Type, hash_secret_raw

ProfileName = Literal["mobile", "desktop", "hsm"]


@dataclass
class Argon2Profile:
    name: ProfileName
    time_cost: int
    memory_cost_kib: int
    parallelism: int


DEFAULT_PROFILES: dict[ProfileName, Argon2Profile] = {
    "mobile": Argon2Profile("mobile", time_cost=2, memory_cost_kib=256 * 1024, parallelism=1),
    "desktop": Argon2Profile("desktop", time_cost=3, memory_cost_kib=512 * 1024, parallelism=2),
    "hsm": Argon2Profile("hsm", time_cost=4, memory_cost_kib=1024 * 1024, parallelism=4),
}


def auto_calibrate(target_ms: int = 400) -> Argon2Profile:
    """Measure performance and pick the most secure profile that meets target."""

    sample_password = b"benchmark-password"
    sample_salt = os.urandom(16)
    chosen: Argon2Profile = DEFAULT_PROFILES["mobile"]
    for candidate in DEFAULT_PROFILES.values():
        start = time.perf_counter()
        hash_secret_raw(
            secret=sample_password,
            salt=sample_salt,
            time_cost=candidate.time_cost,
            memory_cost=candidate.memory_cost_kib,
            parallelism=candidate.parallelism,
            hash_len=32,
            type=Type.ID,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        if elapsed_ms <= target_ms:
            chosen = candidate
        else:
            break
    return chosen


def derive_key(password: str, salt: bytes, *, profile: Argon2Profile | None = None, key_len: int = 32) -> bytes:
    profile = profile or auto_calibrate()
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=profile.time_cost,
        memory_cost=profile.memory_cost_kib,
        parallelism=profile.parallelism,
        hash_len=key_len,
        type=Type.ID,
    )


def entropy_bits(password: str) -> float:
    classes = 0
    classes += 1 if any(c.islower() for c in password) else 0
    classes += 1 if any(c.isupper() for c in password) else 0
    classes += 1 if any(c.isdigit() for c in password) else 0
    classes += 1 if any(not c.isalnum() for c in password) else 0
    charset = {0: 0, 1: 26, 2: 52, 3: 62, 4: 94}[classes]
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)
