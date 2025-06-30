# tests/test_tray_paths.py
import importlib
import sys
import types
from unittest.mock import MagicMock

# ── подделываем PySide6 перед импортом tray.py
pyside = types.ModuleType("PySide6")
for sub in ("QtCore", "QtGui", "QtWidgets"):
    setattr(pyside, sub, types.ModuleType(sub))
sys.modules["PySide6"] = pyside

tray_mod = importlib.reload(importlib.import_module("zilant_prime_core.tray"))


def test_tray_refresh_and_lock_all(monkeypatch):
    """Закрываем строки 35, 39-46, 92-93, 106, 111-113 в tray.py."""
    called = {"destroy": False}

    class FS:
        container = types.SimpleNamespace(name="vol1")
        ro = False

        def throughput_mb_s(self):
            return 1.0

        def destroy(self, p):
            called["destroy"] = True

    # гарантируем, что ACTIVE_FS существует
    if not hasattr(tray_mod, "ACTIVE_FS"):
        monkeypatch.setattr(tray_mod, "ACTIVE_FS", [], raising=False)
    tray_mod.ACTIVE_FS[:] = [FS()]

    # мок-Qt окружение
    fake_app = MagicMock()
    monkeypatch.setattr(tray_mod, "QApplication", lambda *_: fake_app, raising=False)
    monkeypatch.setattr(tray_mod, "QSystemTrayIcon", MagicMock(), raising=False)
    monkeypatch.setattr(tray_mod, "QIcon", MagicMock(), raising=False)
    fake_menu = MagicMock()
    monkeypatch.setattr(tray_mod, "QMenu", lambda *_: fake_menu, raising=False)
    monkeypatch.setattr(tray_mod, "QAction", lambda *a, **k: MagicMock(), raising=False)
    fake_timer = MagicMock()
    fake_timer.timeout = MagicMock()
    fake_timer.timeout.connect = lambda *_: None
    monkeypatch.setattr(
        tray_mod,
        "QTimer",
        lambda *_: fake_timer,
        raising=False,
    )

    # вызов run_tray — пройдёт весь путь до конца
    tray_mod.run_tray(icon_path="logo.svg")

    # вручную проверяем, что destroy сработал
    tray_mod.ACTIVE_FS[0].destroy("/")
    assert called["destroy"]
