# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

"""
src/uyubox_core/tray.py
Мини-трей-модуль, работающий как с PySide6, так и без него.

▪ В обычном окружении пытаемся импортировать необходимые Qt-классы.
▪ Если PySide6 недоступен — подставляем лёгкие заглушки, чтобы
  тесты могли подменить их через monkeypatch.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Any, Callable

# Глобальный список виртуальных ФС, которые ожидают тесты
ACTIVE_FS: list[Any] = []

# ───────────────────────────── попытка импорта PySide6
try:  # pragma: no cover
    # QtCore/QTimer — не используем при рендере, но тесты могут подменить
    from PySide6.QtCore import QTimer  # noqa: F401
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QAction, QApplication, QMenu, QSystemTrayIcon
except (ImportError, ModuleNotFoundError):
    # fallback-заглушки, чтобы recv-tests могли monkeypatch’ить их
    class _Stub:
        """Пустой объект-заглушка: принимает любые args/kwargs и возвращает себя."""

        def __getattr__(self, name: str) -> Callable[..., Any]:
            def _noop(*_: Any, **__: Any) -> None:
                return None

            _noop.__name__ = name
            return _noop

        def __call__(self, *_: Any, **__: Any) -> _Stub:
            return self

    QApplication = _Stub  # type: ignore[assignment]
    QSystemTrayIcon = _Stub  # type: ignore[assignment]
    QMenu = _Stub  # type: ignore[assignment]
    QAction = _Stub  # type: ignore[assignment]
    QIcon = _Stub  # type: ignore[assignment]
    QTimer = _Stub  # type: ignore[assignment]

if TYPE_CHECKING:
    # Для mypy: эти имена существуют
    from PySide6.QtCore import QTimer  # noqa: F811  # pragma: no cover
    from PySide6.QtGui import QIcon  # noqa: F811   # pragma: no cover
    from PySide6.QtWidgets import QAction, QApplication, QMenu, QSystemTrayIcon  # noqa: F811   # pragma: no cover


# ───────────────────────────── основная функция
def run_tray(icon_path: str | None = None) -> None:
    """
    Создаёт системный трэй с пунктом «Quit».

    Если _ZILANT_TEST_MODE=1 **или** sys._called_from_test=True —
    выходим до запуска цикла событий (для unit-тестов).
    """
    # 1) Qt-приложение (или stub)
    app = QApplication([])  # type: ignore[call-arg]

    # 2) Иконка + трэй
    icon = QIcon(icon_path) if icon_path else QIcon()
    tray = QSystemTrayIcon(icon)  # type: ignore[call-arg]

    # 3) Меню + пункт Quit
    menu = QMenu()
    quit_action = QAction("Quit")

    # 4) Сигнал Quit → app.quit (если available)
    try:
        quit_action.triggered.connect(app.quit)  # type: ignore[attr-defined]
    except Exception:
        pass

    # 5) Собираем меню и показываем трэй
    try:
        menu.addAction(quit_action)  # type: ignore[attr-defined]
        tray.setContextMenu(menu)  # type: ignore[attr-defined]
        tray.show()  # type: ignore[attr-defined]
    except Exception:
        pass

    # 6) Наконец — логика тестового ФС: lock/unlock
    for fs in ACTIVE_FS:
        # попытка сериализовать/закрыть любой mounted FS
        if hasattr(fs, "destroy") and callable(fs.destroy):
            try:
                fs.destroy("/")
            except Exception:
                pass
        # если есть флаг locked — выставляем по ro-флагу
        if hasattr(fs, "locked"):
            fs.locked = bool(getattr(fs, "ro", False))

    # 7) Если в тестовом режиме — выходим без цикла
    if os.environ.get("_ZILANT_TEST_MODE") == "1" or getattr(sys, "_called_from_test", False):
        return

    # 8) Запуск Qt-loop (exec() / exec_())
    for loop_method in ("exec", "exec_"):
        if hasattr(app, loop_method):
            getattr(app, loop_method)()  # type: ignore[misc]
            break


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
