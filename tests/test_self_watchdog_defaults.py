# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import zilant_prime_core.utils.self_watchdog as wd


class DummyLock:
    def acquire(self):
        pass


class DummyThread:
    def __init__(self, target, args, daemon):
        # запомним аргументы, чтобы проверить правильность
        self.target = target
        self.args = args
        self.daemon = daemon
        DummyThread.created = True
        DummyThread.args = args

    def start(self):
        # не запускаем реальный цикл
        pass


def test_init_self_watchdog_with_defaults(monkeypatch, tmp_path):
    # создаём "модульный" файл
    mod = tmp_path / "mod.py"
    mod.write_text("x=1")

    # подменяем FileLock, чтобы не блокировать файловую систему
    monkeypatch.setattr(wd, "FileLock", lambda lock_file: DummyLock())
    # подменяем compute_self_hash
    monkeypatch.setattr(wd, "compute_self_hash", lambda fp: "HASHED")
    # подменяем Thread
    monkeypatch.setattr(wd.threading, "Thread", DummyThread)

    # Вызываем без lock_file и module_file
    wd.init_self_watchdog(module_file=str(mod))

    # Проверяем, что поток создался с правильными аргументами
    assert getattr(DummyThread, "created", False)
    # args: (module_file, expected_hash, interval)
    assert DummyThread.args[0] == str(mod)
    assert DummyThread.args[1] == "HASHED"
    assert DummyThread.args[2] == 60
