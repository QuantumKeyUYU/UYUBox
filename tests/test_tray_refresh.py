import pytest

try:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QLabel
except Exception as exc:  # pragma: no cover - optional GUI
    pytest.skip(f"PySide6 unavailable: {exc}", allow_module_level=True)

pytestmark = pytest.mark.qt


def test_tray_refresh(qtbot):
    label = QLabel("x")
    timer = QTimer()

    def _update():
        label.setText("y")

    timer.timeout.connect(_update)
    timer.start(1000)
    qtbot.addWidget(label)
    qtbot.wait(1500)
    assert label.text() == "y"
