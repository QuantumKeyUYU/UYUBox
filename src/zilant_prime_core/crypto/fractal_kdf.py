# SPDX-License-Identifier: MIT
"""Fractal key derivation using a logistic map."""

from __future__ import annotations

import hashlib
from typing import Final

_A: Final = 3.987654321


def fractal_kdf(seed: bytes, *, depth: int = 8) -> bytes:
    """Derive a 32-byte key from ``seed`` using chaotic iterations."""
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if depth <= 0:
        raise ValueError("depth must be positive")

    x = int.from_bytes(hashlib.sha3_256(seed).digest(), "big") / (2**256 - 1)
    for _ in range(depth):
        x = _A * x * (1 - x)
    return hashlib.sha3_256(str(x).encode()).digest()


__all__ = ["fractal_kdf"]
