# SPDX-License-Identifier: MIT
"""Helpers for self-healing container reactions."""

from __future__ import annotations

import os
from pathlib import Path

from zilant_prime_core.crypto.fractal_kdf import fractal_kdf

AUDIO_LOG = Path("self_heal.log")


def rotate_key(old_key: bytes) -> bytes:
    """Return a new key derived from ``old_key``."""
    return fractal_kdf(old_key)


def record_event(info: dict) -> None:
    """Append ``info`` to the self-heal audit log."""
    line = os.fsencode(str(info)) + b"\n"
    with open(AUDIO_LOG, "ab") as fh:
        fh.write(line)


def maybe_self_destruct(path: Path) -> None:
    """Optionally remove ``path`` if ``ZILANT_SELF_DESTRUCT`` is ``1``."""
    if os.environ.get("ZILANT_SELF_DESTRUCT") == "1" and path.exists():
        path.unlink()


__all__ = ["rotate_key", "record_event", "maybe_self_destruct"]
