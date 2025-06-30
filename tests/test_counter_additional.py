# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from zilant_prime_core.counter import DistributedCounter


def test_short_hmac_key(tmp_path):
    with pytest.raises(ValueError):
        DistributedCounter(tmp_path / "c.bin", b"123")


def test_anchor_store(tmp_path, monkeypatch):
    path = tmp_path / "c.bin"
    posted = {}

    def fake_post(url, payload=None, **kwargs):
        posted["url"] = url
        posted["json"] = payload

    monkeypatch.setattr("requests.post", fake_post)
    ctr = DistributedCounter(path, b"k" * 32, anchor_url="http://h")
    assert ctr.increment() == 1
    assert posted["url"] == "http://h"
    assert path.exists()


def test_anchor_keyerror(tmp_path, monkeypatch):
    path = tmp_path / "c.bin"

    def fake_post(*a, **kw):
        raise KeyError("bad")

    monkeypatch.setattr("requests.post", fake_post)
    ctr = DistributedCounter(path, b"k" * 32, anchor_url="http://h")
    ctr._store(1)  # should not raise
