# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import json
import sys
from pathlib import Path
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow, QMessageBox, QTextEdit

from container import get_metadata  # <-- поправлен импорт


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("UYUBox")
        self.resize(800, 600)

        self.status = self.statusBar()
        self.status.showMessage("Готово")

        self.editor = QTextEdit(self)
        self.editor.setReadOnly(True)
        self.setCentralWidget(self.editor)

        self._create_menu()

    def _create_menu(self) -> None:
        menu = self.menuBar()
        file_menu = menu.addMenu("&Файл")

        open_act = QAction(QIcon(), "Открыть контейнер…", self)
        open_act.setShortcut("Ctrl+O")
        open_act.triggered.connect(self.open_container)
        file_menu.addAction(open_act)

        file_menu.addSeparator()
        exit_act = QAction(QIcon(), "Выход", self)
        exit_act.setShortcut("Ctrl+Q")
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        help_menu = menu.addMenu("&Справка")
        about_act = QAction("О программе", self)
        about_act.triggered.connect(self.show_about)
        help_menu.addAction(about_act)

    def open_container(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите .zil-файл контейнера",
            "",
            "UYUBox containers (*.zil);;Все файлы (*)",
        )
        if not path:
            return

        try:
            meta = get_metadata(Path(path))
            pretty = json.dumps(meta, ensure_ascii=False, indent=2)
            self.editor.setPlainText(pretty)
            self.status.showMessage(f"Открыт {Path(path).name}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать метаданные:\n{e}")
            self.status.showMessage("Ошибка при открытии")

    def show_about(self) -> None:
        QMessageBox.information(
            self,
            "О программе UYUBox",
            "UYUBox v0.9.9b2\n© 2025 Zilant Prime Core contributors",
        )


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
