# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["atomic_write", "secure_delete"]


def atomic_write(path: Path, data: bytes) -> None:
    """Write data to ``path`` atomically."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def secure_delete(path: Path) -> None:
    """Overwrite file with zeros and delete it."""
    if not path.exists():
        return
    size = path.stat().st_size
    with open(path, "r+b") as f:
        f.write(b"\x00" * size)
        f.flush()
        os.fsync(f.fileno())
    path.unlink()
