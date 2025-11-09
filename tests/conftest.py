"""Test configuration helpers."""
from __future__ import annotations

import sys
from pathlib import Path


def _ensure_repo_root_on_path() -> None:
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


_ensure_repo_root_on_path()

