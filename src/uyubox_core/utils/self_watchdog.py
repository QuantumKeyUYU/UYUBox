# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from __future__ import annotations

import hashlib
import os
import threading
import time
from filelock import FileLock

__all__ = ["compute_self_hash", "init_self_watchdog"]


def compute_self_hash(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _watchdog_loop(file_path: str, expected_hash: str, interval: float) -> None:
    while True:
        try:
            current = compute_self_hash(file_path)
        except Exception:
            os._exit(134)

        if current != expected_hash:
            os._exit(134)

        time.sleep(interval)


def init_self_watchdog(
    module_file: str | None = None,
    lock_file: str | None = None,
    interval: float = 60.0,
) -> None:
    if module_file is None:
        module_file = os.path.realpath(__file__)
    if lock_file is None:
        lock_file = module_file + ".lock"

    lock = FileLock(lock_file)
    lock.acquire()

    expected_hash = compute_self_hash(module_file)

    t = threading.Thread(
        target=_watchdog_loop,
        args=(module_file, expected_hash, interval),
        daemon=True,
    )
    if not hasattr(t, "start"):
        raise RuntimeError("Thread object missing 'start' method")
    t.start()
