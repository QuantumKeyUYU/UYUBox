# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest
import time

from utils.entropy import get_random_bytes


def test_get_random_bytes_positive():
    data = get_random_bytes(16)
    assert isinstance(data, bytes)
    assert len(data) == 16


def test_get_random_bytes_zero():
    with pytest.raises(ValueError):
        get_random_bytes(0)


def test_get_random_bytes_uses_getrandom(monkeypatch):
    # ensure os.getrandom can be patched even if absent
    monkeypatch.setattr(os, "getrandom", lambda n: b"\x01" * n, raising=False)
    data = get_random_bytes(8)
    assert data == b"\x01" * 8


def test_get_random_bytes_fallback(monkeypatch):
    monkeypatch.delattr(os, "getrandom", raising=False)
    monkeypatch.setattr(time, "sleep", lambda t: None)
    data = get_random_bytes(8)
    assert isinstance(data, bytes)
    assert len(data) == 8
