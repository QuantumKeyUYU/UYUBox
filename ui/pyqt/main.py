from __future__ import annotations

import subprocess
import sys
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QHBoxLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout, QWidget

from uyubox_core.utils.screen_guard import ScreenGuardError, guard


class MainWindow(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Zilant Launcher")

        self.pack_button = QPushButton("Pack")
        self.pack_button.clicked.connect(self.run_pack)

        self.unpack_button = QPushButton("Unpack")
        self.unpack_button.clicked.connect(self.run_unpack)

        self.cancel_button = QPushButton("Panic")
        self.cancel_button.clicked.connect(self.cancel)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)

        self.status = QLabel("Idle")
        self.status.setAlignment(Qt.AlignCenter)

        button_row = QHBoxLayout()
        button_row.addWidget(self.pack_button)
        button_row.addWidget(self.unpack_button)
        button_row.addWidget(self.cancel_button)

        layout = QVBoxLayout(self)
        layout.addLayout(button_row)
        layout.addWidget(self.progress)
        layout.addWidget(self.status)

    def run_pack(self) -> None:
        self._run_command(["zilant", "pack"])

    def run_unpack(self) -> None:
        self._run_command(["zilant", "unpack"])

    def _run_command(self, cmd: list[str]) -> None:
        self.progress.setVisible(True)
        self.status.setText("Running...")
        try:
            subprocess.run(cmd, check=True)
            self.status.setText("Done")
        except Exception as exc:  # nosec - surface to user
            self.status.setText(f"Error: {exc}")
        finally:
            self.progress.setVisible(False)

    def cancel(self) -> None:
        QApplication.instance().quit()


def main(args: list[str] | None = None) -> int:
    try:
        guard.assert_secure()
    except ScreenGuardError as exc:
        print(f"Security check failed: {exc}")
        return 90
    app = QApplication(args or sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
