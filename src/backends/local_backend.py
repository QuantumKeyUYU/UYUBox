"""Local file-based storage backend."""

from __future__ import annotations

import uuid
from pathlib import Path


def store(container: bytes) -> str:
    path = Path(f"container_{uuid.uuid4().hex}.zil")
    path.write_bytes(container)
    return str(path)


def retrieve(uri: str) -> bytes:
    return Path(uri).read_bytes()
