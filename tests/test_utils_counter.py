# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import base64
import json
import pytest

from zilant_prime_core.counter import DistributedCounter, SecurityError


def test_increment_persist_and_reload(tmp_path):
    path = tmp_path / "c.bin"
    ctr1 = DistributedCounter(path, b"k" * 32)
    assert ctr1.increment() == 1
    assert ctr1.increment() == 2

    ctr2 = DistributedCounter(path, b"k" * 32)
    assert ctr2.verify_and_load() == 2
    assert ctr2.increment() == 3
    assert ctr2.verify_and_load() == 3


def test_hmac_tamper_detection(tmp_path):
    path = tmp_path / "c.bin"
    ctr = DistributedCounter(path, b"z" * 32)
    ctr.increment()
    original = ctr._decrypt

    def fake_decrypt(data: bytes) -> bytes:
        plain = original(data)
        obj = json.loads(plain.decode())
        obj["hmac"] = base64.b64encode(b"0" * 32).decode()
        return json.dumps(obj).encode()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(ctr, "_decrypt", fake_decrypt)
    with pytest.raises(SecurityError):
        ctr.verify_and_load()
    monkeypatch.undo()
