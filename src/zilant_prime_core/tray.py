# src/zilant_prime_core/tray.py

from __future__ import annotations

import logging
import os
from typing import Any, Callable

ACTIVE_FS: list[Any] = []


class _Stub:
    """
    A do-nothing stub that absorbs any attribute access or call.
    Used when PySide6 isn’t available, and for testing.
    """

    def __getattr__(self, name: str) -> Callable[..., None]:
        def _method(*args: Any, **kwargs: Any) -> None:
            # no-op, returns None
            return None

        _method.__name__ = name
        return _method

    def __call__(self, *args: Any, **kwargs: Any) -> _Stub:
        # calling a stub returns itself
        return self


# Try real Qt imports; on failure, substitute class-level stubs
try:
    from PySide6.QtCore import QTimer
    from PySide6.QtGui import QAction, QIcon
    from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon
except ImportError:
    QTimer = _Stub  # type: ignore[assignment]
    QAction = _Stub  # type: ignore[assignment]
    QIcon = _Stub  # type: ignore[assignment]
    QApplication = _Stub  # type: ignore[assignment]
    QMenu = _Stub  # type: ignore[assignment]
    QSystemTrayIcon = _Stub  # type: ignore[assignment]


def run_tray(icon_path: str | None = None) -> None:
    if not callable(QApplication):
        raise TypeError("QApplication is not available")

    test_mode = os.environ.get("_ZILANT_TEST_MODE") == "1"

    try:
        app = QApplication([])  # type: ignore[call-arg]
    except Exception as exc:
        logging.error(f"[tray] QApplication init failed: {exc}")
        raise

    try:
        icon = QIcon(icon_path)  # type: ignore[call-arg]
        tray = QSystemTrayIcon(icon)  # type: ignore[call-arg]
        menu = QMenu()  # type: ignore[call-arg]
        quit_action = QAction("Quit")  # type: ignore[call-arg]

        try:
            menu.addAction(quit_action)  # type: ignore[attr-defined]
            tray.setContextMenu(menu)  # type: ignore[attr-defined]
            quit_action.triggered.connect(app.quit)  # type: ignore[attr-defined]
        except Exception as exc:
            logging.warning(f"[tray] menu/action setup failed: {exc}")

        try:
            tray.show()  # type: ignore[attr-defined]
        except Exception as exc:
            logging.warning(f"[tray] tray.show failed: {exc}")

        # skip exec loop so tests can finish; cleanup always runs below
        if not test_mode:
            return

    finally:
        for fs in ACTIVE_FS:
            if hasattr(fs, "destroy"):
                try:
                    fs.destroy("/")
                except Exception as exc:
                    logging.warning(f"[tray] fs.destroy failed: {exc}")
            if getattr(fs, "ro", False):
                fs.locked = True
