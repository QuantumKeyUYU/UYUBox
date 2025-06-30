# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import time

import src.zilant_prime_core.utils.self_watchdog as wd


def test_init_self_watchdog_default_lockfile(monkeypatch):
    # Первый вызов compute_self_hash вернёт хеш, второй — выбросит exception
    calls = {"n": 0}
    exits = {}

    def fake_exit(code):
        exits["code"] = code
        raise SystemExit

    def patched_hash(path):
        calls["n"] += 1
        if calls["n"] == 1:
            return "HASH"
        raise Exception("fail in thread")

    monkeypatch.setattr(os, "_exit", fake_exit)
    monkeypatch.setattr(wd, "compute_self_hash", patched_hash)

    try:
        wd.init_self_watchdog()
        # Даем немного времени на срабатывание потока
        time.sleep(1)
    except SystemExit:
        pass

    assert exits.get("code") == 134, "watchdog должен вызвать os._exit(134) из потока"
