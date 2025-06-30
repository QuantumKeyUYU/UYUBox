# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import builtins
import importlib
import pytest


@pytest.fixture
def reload_module(monkeypatch):
    """Reload screen_guard with optional psutil mocking."""

    def _reload(no_psutil: bool = False):
        if no_psutil:
            orig = builtins.__import__

            def fake_import(name, *args, **kwargs):
                if name == "psutil":
                    raise ImportError
                return orig(name, *args, **kwargs)

            monkeypatch.setattr(builtins, "__import__", fake_import)
        module = importlib.reload(importlib.import_module("zilant_prime_core.utils.screen_guard"))
        return module

    return _reload


def test_no_psutil_skips(reload_module):
    sg = reload_module(no_psutil=True)
    sg.guard.assert_secure()


def test_detect_obs(monkeypatch, reload_module):
    sg = reload_module()

    psutil = pytest.importorskip("psutil")

    class Dummy:
        def __init__(self, name: str) -> None:
            self.info = {"name": name}

    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [Dummy("obs.exe")])
    with pytest.raises(sg.ScreenGuardError):
        sg.ScreenGuard().assert_secure()
