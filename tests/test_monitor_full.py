# tests/test_monitor_full.py
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import importlib
import pytest
from types import SimpleNamespace

mon = importlib.import_module("zilant_prime_core.self_heal.monitor")


def test_monitor_container_importerror(monkeypatch):
    """Если watchdog не установлен — ImportError."""
    monkeypatch.setattr(mon, "Observer", None)
    with pytest.raises(ImportError):
        mon.monitor_container("anypath")


def test_handler_safe_call_and_break(monkeypatch, tmp_path):
    """
    Проверяем _Handler.on_modified:
    - первый шаг (rotate_key) проходит,
    - второй (prove_intact) падает → record_event("self_heal_handler_failed") и break,
      т.е. maybe_self_destruct не вызывается.
    """
    # Собираем все события record_event
    events = []
    monkeypatch.setattr(mon, "record_event", lambda ev: events.append(ev))

    # Успешная ротация ключа
    monkeypatch.setattr(mon, "rotate_key", lambda k: None)
    # Провокация падения на проверке целостности
    monkeypatch.setattr(mon, "prove_intact", lambda d: (_ for _ in ()).throw(RuntimeError("boom-proof")))
    # Следующий шаг — self_destruct — помечаем, если он всё же вызовется
    called_destruct = []
    monkeypatch.setattr(mon, "maybe_self_destruct", lambda path: called_destruct.append(path))

    # Подготовка handler и события
    p = tmp_path / "f.zil"
    p.write_text("data")
    handler = mon._Handler(p)
    event = SimpleNamespace(src_path=str(p))

    # Запуск
    handler.on_modified(event)

    # Должен быть запись модификации
    assert any(ev.get("action") == "modified" for ev in events)

    # Должен быть зафиксирован сбой proof с нашим сообщением
    assert any(ev.get("event") == "self_heal_handler_failed" and "boom-proof" in ev.get("error", "") for ev in events)

    # maybe_self_destruct после падения НЕ вызывается
    assert not called_destruct
