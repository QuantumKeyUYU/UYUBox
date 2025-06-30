# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import os

import zilant_prime_core.utils.self_watchdog as wd


class DummyLockNoArgs:
    def __init__(self, lock_file):
        # запомним, каким именем воспользовался дефолт
        DummyLockNoArgs.lock_file = lock_file

    def acquire(self):
        pass


class DummyThreadNoArgs:
    def __init__(self, target, args, daemon):
        DummyThreadNoArgs.created = True
        DummyThreadNoArgs.args = args

    def start(self):
        pass


def test_init_self_watchdog_no_args(monkeypatch):
    # Подменяем FileLock, compute_self_hash и Thread
    monkeypatch.setattr(wd, "FileLock", DummyLockNoArgs)
    monkeypatch.setattr(wd, "compute_self_hash", lambda fp: "DEFAULT_HASH")
    monkeypatch.setattr(wd.threading, "Thread", DummyThreadNoArgs)

    # Вызываем без аргументов
    wd.init_self_watchdog()

    # Ожидаем, что lock_file = realpath(__file__) + ".lock"
    real_mod = os.path.realpath(wd.__file__)
    assert DummyLockNoArgs.lock_file == real_mod + ".lock"

    # И что поток создался с правильными параметрами
    assert getattr(DummyThreadNoArgs, "created", False)
    mf, h, interv = DummyThreadNoArgs.args
    assert mf == real_mod
    assert h == "DEFAULT_HASH"
    assert interv == 60
