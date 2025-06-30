# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Anti-snapshot detection helpers."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from utils.file_utils import atomic_write
from zilant_prime_core.utils.counter import read_counter

TIMESTAMP_FILE = Path.home() / ".zilant_timestamp"
SUSPICION_THRESHOLD = 300


def read_timestamp() -> Optional[float]:
    """Return stored timestamp or ``None`` if unavailable."""
    try:
        if TIMESTAMP_FILE.exists():
            text = TIMESTAMP_FILE.read_text().strip()
            return float(text)
    except Exception:
        pass
    return None


def write_timestamp(ts: Optional[float] = None) -> None:
    """Write ``ts`` (or current time if ``None``) to ``TIMESTAMP_FILE``."""
    t = time.time() if ts is None else ts
    data = str(t).encode("utf-8")
    tmp = TIMESTAMP_FILE.with_suffix(TIMESTAMP_FILE.suffix + ".tmp")
    atomic_write(tmp, data)
    tmp.replace(TIMESTAMP_FILE)


def detect_snapshot() -> bool:
    """Return ``True`` if a snapshot/rollback is suspected."""
    _ = read_counter()
    saved = read_timestamp()
    now = time.time()
    if saved is not None and abs(now - saved) > SUSPICION_THRESHOLD:
        return True
    write_timestamp(now)
    return False
