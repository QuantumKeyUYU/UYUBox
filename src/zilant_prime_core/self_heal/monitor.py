# SPDX-License-Identifier: MIT
"""File monitor that triggers self-healing reactions."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Callable, Sequence

# watchdog — опциональная зависимость (и никаких ворнингов от линтера)
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover
    FileSystemEventHandler = object  # type: ignore  # pragma: no cover
    Observer = None  # type: ignore  # pragma: no cover

from zilant_prime_core.zkp import prove_intact

from .reaction import maybe_self_destruct, record_event, rotate_key


class _Handler(FileSystemEventHandler):
    def __init__(self, path: Path) -> None:
        self.path = path
        self._key = lambda: b"initial-key".ljust(32, b"\0")
        self._digest = lambda: hashlib.sha3_256(str(self.path).encode()).digest()

    def on_modified(self, event: Any) -> None:
        if getattr(event, "src_path", None) != str(self.path):
            return

        def safe_call(step: Callable[[], Any]) -> bool:
            try:
                step()
                return True
            except Exception as exc:
                record_event(
                    {
                        "event": "self_heal_handler_failed",
                        "file": str(self.path),
                        "action": getattr(step, "__name__", "<lambda>"),
                        "error": str(exc),
                    }
                )
                return False

        steps: Sequence[Callable[[], Any]] = [
            lambda: rotate_key(self._key()),
            lambda: record_event({"file": str(self.path), "action": "modified"}),
            lambda: prove_intact(self._digest()),
            lambda: maybe_self_destruct(self.path),
        ]

        for step in steps:
            if not safe_call(step):
                break


def monitor_container(path: str) -> None:
    """Watch path for modifications and trigger reactions."""
    if Observer is None:
        raise ImportError("watchdog is required for monitor_container")

    p = Path(path)
    handler = _Handler(p)
    observer = Observer()
    observer.schedule(handler, p.parent.as_posix(), recursive=False)
    observer.start()
    try:
        while observer.is_alive():
            time.sleep(0.1)
    finally:
        observer.stop()
        observer.join()
