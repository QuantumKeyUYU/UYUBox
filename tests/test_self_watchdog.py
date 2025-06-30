# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import hashlib
import time

from zilant_prime_core.utils.self_watchdog import compute_self_hash, init_self_watchdog


def test_compute_self_hash(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"abc123")
    h = compute_self_hash(str(p))
    assert h == hashlib.sha256(b"abc123").hexdigest()


def test_watchdog_detects_change(tmp_path, monkeypatch, capsys):
    # Подготовка: файл и lock-файл
    p = tmp_path / "mod.py"
    p.write_text("x=1")
    lock = str(p) + ".lock"

    # Мокаем os._exit **до** инициализации
    import zilant_prime_core.utils.self_watchdog as wd

    called = {}

    def fake_exit(code):
        called["code"] = code
        # выбросим SystemExit, чтобы завершить именно этот поток
        raise SystemExit(code)

    monkeypatch.setattr(wd.os, "_exit", fake_exit)

    # Запускаем watchdog с коротким интервалом
    init_self_watchdog(module_file=str(p), lock_file=lock, interval=0.1)

    # Немного ждём, чтобы фоновой поток успел запустить первую проверку
    time.sleep(0.05)

    # Порча файла: хеш перестанет совпадать
    p.write_text("x=2")

    # Ждём чуть больше одного интервала — fake_exit должен сработать
    time.sleep(0.2)

    # Проверяем, что exit был вызван с кодом 134
    assert called.get("code") == 134, "Watchdog не обнаружил рассинхронизацию хеша"

    # Убедимся, что фоновой поток завершился (нет лишних сообщений)
    # Дадим ещё немного времени — если поток был жив, он бы снова пытался exit
    time.sleep(0.2)
    # Если бы поток был жив, мы бы снова сбросили called, но т.к. он умер, called не меняется
    assert called.get("code") == 134
