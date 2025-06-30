# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest

import zilant_prime_core.utils.self_watchdog as wd


class ThreadNoStart:
    def __init__(self):
        pass


class DummyLock:
    def __init__(self, lock_file):
        DummyLock.lock_file = lock_file

    def acquire(self, timeout=None):
        pass


def test_init_self_watchdog_thread_missing_start(monkeypatch, tmp_path):
    """Провоцируем ветку: thread без метода start."""
    mod = tmp_path / "mymod.py"
    mod.write_text("data")

    monkeypatch.setattr(wd, "FileLock", lambda lf: DummyLock(lf))
    monkeypatch.setattr(wd, "compute_self_hash", lambda fp: "XYZ")
    monkeypatch.setattr(wd.threading, "Thread", lambda *a, **kw: ThreadNoStart())

    with pytest.raises(RuntimeError, match="Thread object missing 'start' method"):
        wd.init_self_watchdog(module_file=str(mod), interval=5)


def test_default_module_file_coverage(monkeypatch):
    """Проверяем ветку: module_file=None, lock_file=None."""

    class DummyLock2:
        def __init__(self, lock_file):
            DummyLock2.lock_file = lock_file

        def acquire(self, timeout=None):
            pass

    class DummyThread2:
        def __init__(self, target, args, daemon):
            DummyThread2.created = True
            DummyThread2.args = args

        def start(self):
            pass

    monkeypatch.setattr(wd, "FileLock", lambda lf: DummyLock2(lf))
    monkeypatch.setattr(wd, "compute_self_hash", lambda fp: "ABC123")
    monkeypatch.setattr(wd.threading, "Thread", DummyThread2)

    wd.init_self_watchdog()  # без аргументов

    real_mod = os.path.realpath(wd.__file__)
    assert DummyThread2.created
    assert DummyThread2.args[0] == real_mod
    assert DummyThread2.args[1] == "ABC123"
    assert DummyThread2.args[2] == 60.0
    assert DummyLock2.lock_file == real_mod + ".lock"


def test_watchdog_loop_triggers_exit(monkeypatch, tmp_path):
    """Провоцируем os._exit(134), когда compute_self_hash бросает исключение."""
    file_path = str(tmp_path / "nofile.py")

    called = {}

    def fake_exit(code):
        called["exit"] = code
        raise SystemExit

    monkeypatch.setattr(wd, "compute_self_hash", lambda fp: (_ for _ in ()).throw(Exception("fail!")))
    monkeypatch.setattr(os, "_exit", fake_exit)

    # Извлекаем глобальную функцию _watchdog_loop напрямую:
    loop = wd.init_self_watchdog.__globals__["_watchdog_loop"]
    with pytest.raises(SystemExit):
        loop(file_path, "IGNORED", 0.0)
    assert called.get("exit") == 134
