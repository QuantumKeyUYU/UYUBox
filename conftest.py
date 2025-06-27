# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import os
import sys
from pathlib import Path

# вставляем папку src/ в начало sys.path, чтобы
# import uyubox_core… брал код именно из src/
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if SRC.is_dir():
    sys.path.insert(0, str(SRC))

os.environ.setdefault("ZILANT_ALLOW_ROOT", "1")

import pytest


@pytest.fixture(autouse=True)
def _disable_screen_guard(monkeypatch):
    """Skip screen guard checks during tests."""
    from uyubox_core.utils import screen_guard

    monkeypatch.setattr(screen_guard.guard, "assert_secure", lambda: None)
    yield
