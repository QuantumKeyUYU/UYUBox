# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import sys

from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)


class MainWindow(QMainWindow):
    """Main application window with basic actions."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("UYUBox")

        self._create_menu()
        self._create_central()

        status = QStatusBar(self)
        status.showMessage("Готово")
        self.setStatusBar(status)

    def create_container_action(self) -> None:
        """Placeholder action for creating a container."""
        QMessageBox.information(self, "UYUBox", "Запущена процедура создания нового контейнера")

    def open_container_action(self) -> None:
        """Placeholder action for opening a container."""
        QMessageBox.information(self, "UYUBox", "Запущена процедура открытия контейнера")

    def _create_menu(self) -> None:
        menu = self.menuBar().addMenu("Файл")

        new_act = QAction("Создать новый контейнер", self)
        menu.addAction(new_act)

        open_act = QAction("Открыть контейнер", self)
        menu.addAction(open_act)

        menu.addSeparator()

        exit_act = QAction("Выход", self)
        exit_act.triggered.connect(self.close)
        menu.addAction(exit_act)

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

        central.setLayout(layout)
        self.setCentralWidget(central)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
