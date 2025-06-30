# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

from __future__ import annotations

import argon2.low_level as a2
from typing import cast

__all__ = ["derive_key"]

# Parameters from specification
_MEMORY_KIB = 500 * 1024  # 500 MiB
_TIME_COST = 8
_PARALLELISM = 4
_KEY_LENGTH = 32


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte key from ``password`` and ``salt`` using Argon2id."""
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    return cast(
        bytes,
        a2.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=_TIME_COST,
            memory_cost=_MEMORY_KIB,
            parallelism=_PARALLELISM,
            hash_len=_KEY_LENGTH,
            type=a2.Type.ID,
        ),
    )
