# tests/test_container_tamper_exceptions.py
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

import audit_ledger
import container
import zilant_prime_core.notify as notify_mod


def test_unpack_file_tamper_detected_notify_exceptions(tmp_path, monkeypatch):
    # Упаковываем "сломанный" контейнер
    cont = tmp_path / "broken_ex.zil"
    cont.write_bytes(b"really invalid")

    # record_action бросает
    def bad_record(action, data):
        raise RuntimeError("record failed")

    monkeypatch.setattr(audit_ledger, "record_action", bad_record)

    # Notifier.__init__ бросает
    def bad_init(self):
        raise RuntimeError("notifier init failed")

    monkeypatch.setattr(notify_mod.Notifier, "__init__", bad_init, raising=True)

    # unpack_file должен всё равно поднять ValueError, не взрываясь раньше
    with pytest.raises(ValueError):
        container.unpack_file(cont, tmp_path / "out", b"\0" * 32)
