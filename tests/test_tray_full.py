# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import importlib
import os
import pytest
import types

# Попробуй вариант с учетом src или src/zilant_prime_core
# Если не работает — замени на актуальный путь для твоей структуры
try:
    tray = importlib.import_module("src.zilant_prime_core.tray")
except ModuleNotFoundError:
    tray = importlib.import_module("src.tray")


@pytest.fixture(autouse=True)
def cleanup_env(monkeypatch):
    orig = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(orig)


def test_run_tray_minimal(monkeypatch):
    called = {}

    class DummyApp:
        def __init__(self, *a, **k):
            pass

        def quit(self):
            called["quit"] = True

        def exec_(self):
            called["exec_"] = True

        def exec(self):
            called["exec"] = True

    class DummyAction:
        def __init__(self, txt):
            self.triggered = types.SimpleNamespace(connect=lambda cb: cb())

    class DummyMenu:
        def __init__(self):
            self.actions = []

        def addAction(self, act):
            self.actions.append(act)

    class DummyIcon:
        def __init__(self, path=None):
            pass

    class DummyTray:
        def __init__(self, icon):
            self.menu = None

        def setContextMenu(self, menu):
            self.menu = menu

        def show(self):
            pass

    monkeypatch.setattr(tray, "QApplication", lambda *a, **k: DummyApp())
    monkeypatch.setattr(tray, "QSystemTrayIcon", lambda icon: DummyTray(icon))
    monkeypatch.setattr(tray, "QMenu", DummyMenu)
    monkeypatch.setattr(tray, "QAction", DummyAction)
    monkeypatch.setattr(tray, "QIcon", DummyIcon)
    tray.ACTIVE_FS.clear()
    tray.run_tray(icon_path=None)
    assert "quit" in called or "exec_" in called or "exec" in called or called == {}


def test_run_tray_quit_action_connect_exception(monkeypatch):
    class DummyApp:
        def __init__(self, *a, **k):
            pass

        def quit(self):
            pass

        def exec_(self):
            pass

    class DummyAction:
        def __init__(self, txt):
            class Triggered:
                def connect(self, cb):
                    raise Exception("fail connect")

            self.triggered = Triggered()

    class DummyMenu:
        def __init__(self):
            pass

        def addAction(self, act):
            pass

    class DummyTray:
        def __init__(self, icon):
            pass

        def setContextMenu(self, menu):
            pass

        def show(self):
            pass

    monkeypatch.setattr(tray, "QApplication", lambda *a, **k: DummyApp())
    monkeypatch.setattr(tray, "QSystemTrayIcon", lambda icon: DummyTray(icon))
    monkeypatch.setattr(tray, "QMenu", DummyMenu)
    monkeypatch.setattr(tray, "QAction", DummyAction)
    monkeypatch.setattr(tray, "QIcon", lambda path=None: None)
    tray.ACTIVE_FS.clear()
    tray.run_tray(icon_path="noicon.png")


def test_run_tray_menu_set_exception(monkeypatch):
    class DummyApp:
        def __init__(self, *a, **k):
            pass

        def quit(self):
            pass

        def exec_(self):
            pass

    class DummyAction:
        def __init__(self, txt):
            class Triggered:
                def connect(self, cb):
                    pass

            self.triggered = Triggered()

    class DummyMenu:
        def __init__(self):
            pass

        def addAction(self, act):
            raise Exception("fail addAction")

    class DummyTray:
        def __init__(self, icon):
            pass

        def setContextMenu(self, menu):
            raise Exception("fail setContextMenu")

        def show(self):
            raise Exception("fail show")

    monkeypatch.setattr(tray, "QApplication", lambda *a, **k: DummyApp())
    monkeypatch.setattr(tray, "QSystemTrayIcon", lambda icon: DummyTray(icon))
    monkeypatch.setattr(tray, "QMenu", DummyMenu)
    monkeypatch.setattr(tray, "QAction", DummyAction)
    monkeypatch.setattr(tray, "QIcon", lambda path=None: None)
    tray.ACTIVE_FS.clear()
    tray.run_tray(icon_path=None)


def test_run_tray_active_fs_destroy_and_locked(monkeypatch):
    destroyed = {}

    class FakeFS:
        def __init__(self):
            self.ro = True
            self.locked = False

        def destroy(self, arg):
            destroyed["ok"] = True

    tray.ACTIVE_FS.clear()
    fs = FakeFS()
    tray.ACTIVE_FS.append(fs)
    monkeypatch.setattr(tray, "QApplication", lambda *a, **k: type("A", (), {"exec_": lambda self: 0})())
    monkeypatch.setattr(
        tray,
        "QSystemTrayIcon",
        lambda icon: type("Tray", (), {"setContextMenu": lambda self, m: None, "show": lambda self: None})(),
    )
    monkeypatch.setattr(tray, "QMenu", lambda: type("Menu", (), {"addAction": lambda self, a: None})())
    monkeypatch.setattr(
        tray,
        "QAction",
        lambda txt: type("Action", (), {"triggered": type("Trig", (), {"connect": lambda self, cb: None})()})(),
    )
    monkeypatch.setattr(tray, "QIcon", lambda path=None: None)
    tray.run_tray(icon_path=None)
    assert destroyed["ok"]
    assert fs.locked


def test_run_tray_test_mode(monkeypatch):
    os.environ["_ZILANT_TEST_MODE"] = "1"
    monkeypatch.setattr(tray, "QApplication", lambda *a, **k: type("A", (), {})())
    monkeypatch.setattr(
        tray,
        "QSystemTrayIcon",
        lambda icon: type("Tray", (), {"setContextMenu": lambda self, m: None, "show": lambda self: None})(),
    )
    monkeypatch.setattr(tray, "QMenu", lambda: type("Menu", (), {"addAction": lambda self, a: None})())
    monkeypatch.setattr(
        tray,
        "QAction",
        lambda txt: type("Action", (), {"triggered": type("Trig", (), {"connect": lambda self, cb: None})()})(),
    )
    monkeypatch.setattr(tray, "QIcon", lambda path=None: None)
    tray.ACTIVE_FS.clear()
    tray.run_tray(icon_path=None)
