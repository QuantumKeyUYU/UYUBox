import os
import pytest

pytest.importorskip("PyQt5.QtWidgets")

from PyQt5.QtWidgets import QApplication
from ui.pyqt.main import MainWindow


def test_mainwindow_creation():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    win = MainWindow()
    assert win.pack_button.text() == "Pack"
    assert win.unpack_button.text() == "Unpack"
    assert win.cancel_button.text() == "Panic"
    win.close()
    app.quit()
