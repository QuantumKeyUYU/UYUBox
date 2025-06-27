# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Persistent monotonic counter utilities."""

from __future__ import annotations

from pathlib import Path

from utils.file_utils import atomic_write

COUNTER_FILE = Path.home() / ".zilant_counter"
BACKUP_COUNTER_FILE = Path.home() / ".zilant_counter_backup"


def read_counter() -> int:
    """Return the stored counter value or ``0`` if unavailable."""
    for path in (COUNTER_FILE, BACKUP_COUNTER_FILE):
        try:
            if path.exists():
                text = path.read_text().strip()
                return int(text)
        except Exception:
            continue
    return 0


def write_counter(new_value: int) -> None:
    """Write ``new_value`` atomically to the counter files."""
    if not isinstance(new_value, int) or new_value < 0:
        raise ValueError("Counter must be non-negative integer")

    data = str(new_value).encode("utf-8")

    tmp_main = COUNTER_FILE.with_suffix(COUNTER_FILE.suffix + ".tmp")
    atomic_write(tmp_main, data)
    tmp_main.replace(COUNTER_FILE)

    tmp_bkp = BACKUP_COUNTER_FILE.with_suffix(BACKUP_COUNTER_FILE.suffix + ".tmp")
    atomic_write(tmp_bkp, data)
    tmp_bkp.replace(BACKUP_COUNTER_FILE)


def increment_counter() -> None:
    """Increase the stored counter by one."""
    current = read_counter()
    write_counter(current + 1)
