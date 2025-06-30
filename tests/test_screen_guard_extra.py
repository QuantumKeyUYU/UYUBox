# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from zilant_prime_core.utils import screen_guard


def test_iter_proc_names_empty():
    sg = screen_guard.ScreenGuard()
    sg._psutil = None
    assert list(sg._iter_proc_names()) == []


def test_iter_proc_names_exception():
    sg = screen_guard.ScreenGuard()

    class DummyPsutil:
        def process_iter(self, attrs=None):
            class DummyProc:
                @property
                def info(self):
                    raise Exception("fail")

            return [DummyProc()]

    sg._psutil = DummyPsutil()
    # Даже если proc.info бросает исключение, цикл должен продолжаться, но ничего не yield
    assert list(sg._iter_proc_names()) == []


def test_assert_secure_no_procs():
    sg = screen_guard.ScreenGuard()
    sg._psutil = None
    sg.assert_secure()  # Просто должен пройти, не выбрасывая ошибку


def test_assert_secure_blacklist():
    sg = screen_guard.ScreenGuard()

    class DummyPsutil:
        def process_iter(self, attrs=None):
            class DummyProc:
                info = {"name": "obs.exe"}

            return [DummyProc()]

    sg._psutil = DummyPsutil()
    with pytest.raises(screen_guard.ScreenGuardError):
        sg.assert_secure()
