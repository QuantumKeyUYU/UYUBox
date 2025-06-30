# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import hashlib
import random
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..notify import Notifier
from .secure_logging import get_secure_logger


class HoneyfileError(Exception):
    pass


def create_honeyfile(path: str) -> None:
    marker = f"HONEYFILE:{random.randint(1000, 9999)}"
    p = Path(path)
    content = p.read_text(encoding="utf-8") if p.exists() else ""
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{content}\n{marker}")


def is_honeyfile(path: str) -> bool:
    try:
        content = Path(path).read_text(encoding="utf-8")
        return "HONEYFILE:" in content
    except Exception:
        return False


def check_tmp_for_honeyfiles(tmp_dir: str | None = None) -> None:
    """Scan temporary directory for honeyfiles in a secure, portable way."""
    if tmp_dir is not None:
        check_dir = Path(tmp_dir)
    else:
        # Use the most secure and portable way to get temp directory
        check_dir = Path(tempfile.gettempdir())  # pragma: no cover
    for f in check_dir.iterdir():
        if not f.is_file():
            continue
        if is_honeyfile(str(f)):
            raise HoneyfileError(f"Honeyfile detected: {f}")


@dataclass
class _HoneyfileEntry:
    path: Path
    digest: str
    atime: float


class HoneyfileManager:
    """Manage honeyfiles inside a container."""

    def __init__(self) -> None:
        self._entries: list[_HoneyfileEntry] = []
        self._log = get_secure_logger()
        self._notifier = Notifier()

    def create_honeyfile(self, container_path: str | Path, filename: str) -> Path:
        """Create a honeyfile and register it for monitoring."""
        dest = Path(container_path) / filename
        create_honeyfile(str(dest))
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        entry = _HoneyfileEntry(dest, digest, dest.stat().st_atime)
        self._entries.append(entry)
        self._log.log("honeyfile_created", path=str(dest))
        return dest

    def check_for_access(self) -> None:
        """Check registered honeyfiles for access and send notifications."""
        for entry in self._entries:
            try:
                stat = entry.path.stat()
            except FileNotFoundError:
                continue
            if stat.st_atime > entry.atime:
                self._log.log("honeyfile_accessed", path=str(entry.path))
                self._notifier.notify(f"Honeyfile accessed: {entry.path}")
                entry.atime = stat.st_atime
