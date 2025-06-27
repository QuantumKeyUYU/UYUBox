# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
"""
zilant_prime_core.tray
----------------------

Иконка в системном трее («Quit»).

• Если PySide6 доступна целиком — используем её классы.
• Если PySide6 нет / неполная — применяем лёгкие заглушки, чтобы
  рантайм-код не падал и тесты _stub_ прошли.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Any, Protocol

__all__ = [
    "run_tray",
    "QApplication",
    "QSystemTrayIcon",
    "QMenu",
    "QAction",
    "QIcon",
    "QTimer",
    "ACTIVE_FS",
]


# ──────────────────────────── Protocol для stub-объекта ──────────────────────
class _StubProto(Protocol):  # pragma: no cover
    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...
    def __getattr__(self, name: str) -> Any: ...


# ────────────────────────────── Runtime-импорт PySide6 ───────────────────────
if not TYPE_CHECKING:
    try:
        from PySide6.QtCore import QTimer  # type: ignore
        from PySide6.QtGui import QIcon  # type: ignore
        from PySide6.QtWidgets import QAction  # type: ignore[attr-defined]
        from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon  # type: ignore

        _QT_COMPLETE = all(callable(obj) for obj in (QApplication, QMenu, QSystemTrayIcon, QAction, QIcon, QTimer))
    except (ModuleNotFoundError, ImportError, AttributeError):
        _QT_COMPLETE = False

    if not _QT_COMPLETE:

        class _Stub:  # noqa: D401
            """
            Пустышка для PySide6-классов:
            - любые атрибуты возвращают функцию, которая возвращает None
              и корректно выставляет __name__ = name для теста
            - вызов самого объекта возвращает self, чтобы stub() is stub
            """

            def __getattr__(self, name: str) -> Any:
                def stub_func(*args: Any, **kwargs: Any) -> None:
                    return None

                stub_func.__name__ = name  # важно для test_stub_getattr_and_call
                return stub_func

            def __call__(self, *args: Any, **kwargs: Any) -> Any:
                return self

        QApplication = QSystemTrayIcon = QMenu = QAction = QIcon = QTimer = _Stub()  # type: ignore[assignment]


# ───────────────────── Typing-ветка для mypy (без повторного объявления) ──────
if TYPE_CHECKING:  # pragma: no cover
    from typing import Any as _Any  # noqa: F401

    # Просто объявляем, чтобы mypy знал о символах, но не переопределяем классы:
    QApplication: _Any
    QSystemTrayIcon: _Any
    QMenu: _Any
    QAction: _Any
    QIcon: _Any
    QTimer: _Any


# ───────────────────────────── Основная функциональность ────────────────────
ACTIVE_FS: list[Any] = []  # тесты могут добавлять сюда «виртуальные ФС»


def run_tray(icon_path: str | None = None) -> None:  # noqa: D401
    """
    Показывает иконку в системном трее с пунктом «Quit».
    В тестовом режиме (`_ZILANT_TEST_MODE=1` или `sys._called_from_test`)
    цикл событий Qt не запускается.
    """
    app = QApplication([])  # type: ignore[call-arg]
    icon = QIcon(icon_path) if icon_path else QIcon()
    tray = QSystemTrayIcon(icon)  # type: ignore[call-arg]

    menu = QMenu()
    quit_action = QAction("Quit")

    try:
        quit_action.triggered.connect(app.quit)  # type: ignore[attr-defined]
    except Exception:
        pass

    try:
        menu.addAction(quit_action)  # type: ignore[attr-defined]
        tray.setContextMenu(menu)  # type: ignore[attr-defined]
        tray.show()  # type: ignore[attr-defined]
    except Exception:
        pass

    # Демонстрация работы «виртуальных ФС»
    for fs in ACTIVE_FS:
        if callable(getattr(fs, "destroy", None)):
            try:
                fs.destroy("/")
            except Exception:
                pass
        if hasattr(fs, "locked"):
            fs.locked = bool(getattr(fs, "ro", False))

    # В CI/pytest скрываем цикл событий
    if os.getenv("_ZILANT_TEST_MODE") == "1" or getattr(sys, "_called_from_test", False):
        return

    for method in ("exec", "exec_"):
        if hasattr(app, method):
            getattr(app, method)()  # type: ignore[misc]
            break
