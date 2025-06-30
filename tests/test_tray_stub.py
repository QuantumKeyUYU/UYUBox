# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import importlib


def get_tray_module():
    try:
        return importlib.import_module("src.zilant_prime_core.tray")
    except ModuleNotFoundError:
        return importlib.import_module("src.tray")


def test_stub_getattr_and_call():
    tray = get_tray_module()
    stub = tray._Stub()
    fn = stub.some_method
    assert callable(fn)
    assert fn() is None
    assert fn.__name__ == "some_method"
    assert stub() is stub


def test_run_tray_active_fs_destroy_and_locked_edge(monkeypatch):
    tray = get_tray_module()
    destroyed = {}

    class BadFS:
        def __init__(self):
            self.ro = True
            self.locked = False

        def destroy(self, arg):
            destroyed["fail"] = True
            raise Exception("boom")

    fs = BadFS()
    tray.ACTIVE_FS.clear()
    tray.ACTIVE_FS.append(fs)
    # Мокаем все зависимости трея, чтобы не было ошибок GUI
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
    tray.run_tray(icon_path=None)
    assert destroyed["fail"]
    assert fs.locked


# Примечание: TYPE_CHECKING-импорты покрывать не требуется.
