# hash_challenge.py
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import time
from hashlib import sha256
from pathlib import Path

_HC_CACHE: dict[str, str] = {}


def hash_challenge(path: str) -> str:
    """Return cached daily challenge hash for given file path."""
    key = os.path.abspath(path)
    if key in _HC_CACHE:
        return _HC_CACHE[key]
    date_str = time.strftime("%Y-%m-%d")
    try:
        content = Path(key).read_bytes()
    except Exception:
        content = b""
    digest = sha256(date_str.encode("utf-8") + content).hexdigest()
    _HC_CACHE[key] = digest
    return digest


def generate_daily_challenge() -> str:  # pragma: no cover
    """Create or read the single daily challenge file in ~/.zilant."""
    date_str = time.strftime("%Y-%m-%d")
    home = os.getenv("HOME") or str(Path.home())
    base_dir = Path(home) / ".zilant"
    base_dir.mkdir(parents=True, exist_ok=True)
    db_file = base_dir / "challenge_db"
    if db_file.exists():
        return db_file.read_text()
    challenge = sha256(date_str.encode("utf-8")).hexdigest()
    db_file.write_text(challenge)
    return challenge
