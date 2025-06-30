# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Self‑check watchdog in two processes."""

from __future__ import annotations

import hashlib
import multiprocessing as _mp
import os
import sys
import time
from pathlib import Path
from typing import Any, Iterable

# export the real multiprocessing primitives so tests can monkey‑patch them
Process = _mp.Process
Queue = _mp.Queue

__all__ = ["Watchdog", "_hash_sources", "_zeroize", "Process", "Queue"]

_DEF_DIR = Path(__file__).resolve().parent


def _hash_sources(paths: Iterable[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.read_bytes())
    return h.hexdigest()


def _zeroize() -> None:
    """
    Wipe sensitive data and exit the entire program with the sentinel code 134.

    Any exceptions raised by zeroization/notification routines are ignored to
    guarantee the process terminates.
    """
    try:
        from zilant_prime_core.utils.secure_logging import zeroize as log_zeroize

        log_zeroize()
        from zilant_prime_core.notify import Notifier

        Notifier().notify("watchdog triggered")
    except Exception:
        pass
    sys.exit(134)


def _proc_a(watch_dir: Path, expected: str, interval: float, q: Queue[Any]) -> None:
    files = list(watch_dir.rglob("*.py"))
    while True:
        if _hash_sources(files) != expected:
            _zeroize()
        q.put(time.monotonic())
        time.sleep(interval)


def _proc_b(pid_a: int, q: Queue[Any], interval: float) -> None:
    last = time.monotonic()
    while True:
        try:
            last = q.get(timeout=interval * 1.5)
        except FileNotFoundError:  # nosec
            pass
        try:
            os.kill(pid_a, 0)
        except Exception:
            _zeroize()
        if time.monotonic() - last > interval * 2:
            _zeroize()
        time.sleep(interval)


class Watchdog:
    """Run two co‑operating processes that continuously verify code integrity."""

    def __init__(self, build_hash: str, interval_s: float, watch_dir: Path | None = None) -> None:
        self.build_hash = build_hash
        self.interval_s = interval_s
        self.watch_dir = watch_dir or _DEF_DIR
        self._q: Queue[Any] | None = None
        self._a: Process | None = None
        self._b: Process | None = None

    def start(self) -> None:
        q: Queue[Any] = Queue()
        self._q = q
        self._a = Process(target=_proc_a, args=(self.watch_dir, self.build_hash, self.interval_s, q))
        self._a.start()
        self._b = Process(target=_proc_b, args=(self._a.pid, q, self.interval_s))
        self._b.start()

    def stop(self) -> None:
        if self._a is not None:
            self._a.terminate()
            self._a.join()
        if self._b is not None:
            self._b.terminate()
            self._b.join()
