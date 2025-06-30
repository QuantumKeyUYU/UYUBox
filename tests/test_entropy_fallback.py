# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

from utils import entropy


def test_fallback(monkeypatch):
    if hasattr(entropy.os, "getrandom"):
        monkeypatch.delattr(entropy.os, "getrandom", raising=False)
    data = entropy.get_random_bytes(8)
    assert isinstance(data, bytes) and len(data) == 8
