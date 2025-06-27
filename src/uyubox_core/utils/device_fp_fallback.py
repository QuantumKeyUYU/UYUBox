# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
"""Fallback device fingerprint utilities."""

from __future__ import annotations

import time
from pathlib import Path
from typing import cast

from crypto_core import hash_sha3

__all__ = ["device_fp_fallback"]


def _read_cpuinfo(path: str) -> bytes:  # pragma: no cover
    """Read raw bytes from *path* (split for testability & coverage)."""
    return Path(path).read_bytes()


def device_fp_fallback(cpuinfo_path: str = "/proc/cpuinfo") -> str:
    """Return SHA3‑256 fingerprint of ``cpuinfo_path`` or monotonic fallback."""
    try:
        data = _read_cpuinfo(cpuinfo_path)
    except Exception:
        data = str(time.monotonic_ns()).encode()  # pragma: no cover
    return cast(str, hash_sha3(data, hex_output=True))
