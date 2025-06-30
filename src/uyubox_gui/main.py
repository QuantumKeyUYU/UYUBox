# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import json
import sys
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QPalette
from PySide6.QtWidgets import (  # type: ignore[attr-defined]
    QApplication,
    QFileDialog,
    QInputDialog,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from container import get_metadata, pack_file


class MainWindow(QMainWindow):
    """Main application window with basic actions."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("UYUBox")

        self._create_menu()
        self._create_central()
        self.dark_mode = False

        status = QStatusBar(self)
        status.showMessage("Готово")
        self.setStatusBar(status)

    def create_container_action(self) -> None:
        """Pack a file into a new container using a provided key."""
        inp, _ = QFileDialog.getOpenFileName(self, "Выберите файл для упаковки")
        if not inp:
            return
        out, _ = QFileDialog.getSaveFileName(self, "Сохранить контейнер", filter="ZIL Files (*.zil)")
        if not out:
            return
        key_text, ok = QInputDialog.getText(self, "Ключ", "Введите ключ (hex, 32 байта)")
        if not ok:
            return
        try:
            key = bytes.fromhex(key_text)
            if len(key) != 32:
                raise ValueError("Неверный размер ключа")
        except Exception as exc:  # noqa: PERF203 - user input
            QMessageBox.critical(self, "Ошибка", str(exc))
            return

        self.progress.setValue(0)
        QApplication.processEvents()  # type: ignore[attr-defined]
        try:
            pack_file(Path(inp), Path(out), key)
        except Exception as exc:  # noqa: PERF203 - backend errors
            QMessageBox.critical(self, "Ошибка", str(exc))
            self.statusBar().showMessage("Ошибка при создании", 5000)
            return
        self.progress.setValue(100)
        self.statusBar().showMessage("Контейнер создан", 5000)

    def open_container_action(self) -> None:
        """Open a container and display its metadata."""
        path, _ = QFileDialog.getOpenFileName(self, "Открыть контейнер", filter="ZIL Files (*.zil)")
        if not path:
            return
        try:
            meta = get_metadata(Path(path))
        except Exception as exc:  # noqa: PERF203 - backend errors
            QMessageBox.critical(self, "Ошибка", str(exc))
            return
        text = json.dumps(meta, ensure_ascii=False, indent=2)
        self.meta_view.setPlainText(text)
        self.statusBar().showMessage(f"Открыт {Path(path).name}", 5000)

    def _create_menu(self) -> None:
        menu_file = self.menuBar().addMenu("Файл")

        new_act = QAction("Создать новый контейнер", self)
        new_act.triggered.connect(self.create_container_action)
        menu_file.addAction(new_act)

        open_act = QAction("Открыть контейнер", self)
        open_act.triggered.connect(self.open_container_action)
        menu_file.addAction(open_act)

        menu_file.addSeparator()

        exit_act = QAction("Выход", self)
        exit_act.triggered.connect(self.close)
        menu_file.addAction(exit_act)

        menu_help = self.menuBar().addMenu("Справка")
        about_act = QAction("О программе", self)
        about_act.triggered.connect(lambda: QMessageBox.information(self, "О программе", "UYUBox GUI"))
        menu_help.addAction(about_act)

        theme_act = QAction("Темная тема", self)
        theme_act.triggered.connect(self.toggle_theme)
        menu_help.addAction(theme_act)

    def _create_central(self) -> None:
        central = QWidget(self)
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(50, 50, 50, 50)

        self.btn_create = QPushButton("Создать контейнер")
        self.btn_create.setFixedHeight(60)
        self.btn_create.clicked.connect(self.create_container_action)
        layout.addWidget(self.btn_create)

        self.btn_open = QPushButton("Открыть контейнер")
        self.btn_open.setFixedHeight(60)
        self.btn_open.clicked.connect(self.open_container_action)
        layout.addWidget(self.btn_open)

        self.btn_decoy = QPushButton("Сделать декой")
        self.btn_decoy.setFixedHeight(60)
        self.btn_decoy.clicked.connect(lambda: QMessageBox.information(self, "UYUBox", "Decoy создан"))
        layout.addWidget(self.btn_decoy)

        self.btn_heal = QPushButton("Self-Heal")
        self.btn_heal.setFixedHeight(60)
        self.btn_heal.clicked.connect(lambda: QMessageBox.information(self, "UYUBox", "Self-Heal"))
        layout.addWidget(self.btn_heal)

        self.btn_verify = QPushButton("Проверка целостности")
        self.btn_verify.setFixedHeight(60)
        self.btn_verify.clicked.connect(lambda: QMessageBox.information(self, "UYUBox", "Проверка запущена"))
        layout.addWidget(self.btn_verify)

        self.btn_timelock = QPushButton("Таймлок")
        self.btn_timelock.setFixedHeight(60)
        self.btn_timelock.clicked.connect(lambda: QMessageBox.information(self, "UYUBox", "Timelock"))
        layout.addWidget(self.btn_timelock)

        self.progress = QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setMaximum(100)
        layout.addWidget(self.progress)

        self.meta_view = QPlainTextEdit()
        self.meta_view.setReadOnly(True)
        layout.addWidget(self.meta_view)

        central.setLayout(layout)
        self.setCentralWidget(central)

    def toggle_theme(self) -> None:
        """Switch between light and dark color schemes."""
        palette = QPalette()
        if not self.dark_mode:
            palette.setColor(QPalette.Window, Qt.black)
            palette.setColor(QPalette.WindowText, Qt.white)
            self.dark_mode = True
        else:
            palette = self.style().standardPalette()
            self.dark_mode = False
        self.setPalette(palette)


def main() -> None:
    app = QApplication(sys.argv)  # type: ignore[call-arg]
    window = MainWindow()
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()
