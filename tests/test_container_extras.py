# tests/test_container_extras.py
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
from cryptography.exceptions import InvalidTag

import audit_ledger
import container
from zilant_prime_core.notify import Notifier


def test_get_open_attempts_counts(tmp_path):
    # pack a small plaintext file
    src = tmp_path / "data.txt"
    src.write_text("hello")
    cont = tmp_path / "c.zil"
    key = b"k" * 32

    # no unpacks yet
    container.pack_file(src, cont, key)
    assert container.get_open_attempts(cont) == 0

    # successful unpack → count increments
    dest = tmp_path / "out"
    container.unpack_file(cont, dest, key)
    assert container.get_open_attempts(cont) == 1

    # failing unpack (wrong key) → InvalidTag and count increments again
    with pytest.raises(InvalidTag):
        container.unpack_file(cont, tmp_path / "fail", b"x" * 32)
    assert container.get_open_attempts(cont) == 2


class FakeNotifier:
    def __init__(self):
        self.called = False

    def notify(self, msg):
        self.called = True


def test_unpack_file_tamper_detected(tmp_path, monkeypatch):
    # create a broken container (invalid format)
    cont = tmp_path / "broken.zil"
    cont.write_bytes(b"not a valid container")

    # intercept record_action
    recorded = {}

    def fake_record(action, data):
        recorded["action"] = action
        recorded["data"] = data

    monkeypatch.setattr(audit_ledger, "record_action", fake_record)

    # intercept Notifier.notify
    monkeypatch.setattr(Notifier, "__init__", lambda self: None)
    fake_notifier = FakeNotifier()
    monkeypatch.setattr(Notifier, "notify", lambda self, msg: setattr(fake_notifier, "called", True))

    # unpack_file should raise ValueError and trigger our hooks
    with pytest.raises(ValueError):
        container.unpack_file(cont, tmp_path / "out", b"k" * 32)

    assert recorded.get("action") == "tamper_detected"
    assert "file" in recorded.get("data", {})
    assert fake_notifier.called
