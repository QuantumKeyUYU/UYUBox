# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import json
import os
import sys
from pathlib import Path
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QInputDialog,
    QMainWindow,
    QMessageBox,
    QTextEdit,
)

from container import get_metadata, pack_file, unpack_file
from utils.logging import get_logger
from zilant_prime_core.utils import decoy

logger = get_logger("gui")
from .translations import LANGUAGES, tr


class MainWindow(QMainWindow):
    def __init__(self, lang: str = "en") -> None:
        super().__init__()
        self.lang = lang if lang in LANGUAGES else "en"
        self.setWindowTitle("UYUBox")
        self.resize(800, 600)

        self.status = self.statusBar()

        self.editor = QTextEdit(self)
        self.editor.setReadOnly(True)
        self.setCentralWidget(self.editor)

        self._create_menu()
        self._retranslate()

    def _create_menu(self) -> None:
        menu = self.menuBar()
        self.file_menu = menu.addMenu("")

        self.open_act = QAction(QIcon(), "", self)
        self.open_act.setShortcut("Ctrl+O")
        self.open_act.triggered.connect(self.open_container)
        self.file_menu.addAction(self.open_act)

        self.pack_act = QAction(QIcon(), "", self)
        self.pack_act.triggered.connect(self.pack_file_gui)
        self.file_menu.addAction(self.pack_act)

        self.unpack_act = QAction(QIcon(), "", self)
        self.unpack_act.triggered.connect(self.unpack_file_gui)
        self.file_menu.addAction(self.unpack_act)

        self.decoy_act = QAction(QIcon(), "", self)
        self.decoy_act.triggered.connect(self.create_decoy_gui)
        self.file_menu.addAction(self.decoy_act)

        self.sweep_act = QAction(QIcon(), "", self)
        self.sweep_act.triggered.connect(self.sweep_decoys_gui)
        self.file_menu.addAction(self.sweep_act)

        self.file_menu.addSeparator()
        self.exit_act = QAction(QIcon(), "", self)
        self.exit_act.setShortcut("Ctrl+Q")
        self.exit_act.triggered.connect(self.close)
        self.file_menu.addAction(self.exit_act)

        self.lang_menu = menu.addMenu("")
        self.lang_en_act = QAction("", self)
        self.lang_en_act.triggered.connect(lambda: self.set_language("en"))
        self.lang_menu.addAction(self.lang_en_act)
        self.lang_ru_act = QAction("", self)
        self.lang_ru_act.triggered.connect(lambda: self.set_language("ru"))
        self.lang_menu.addAction(self.lang_ru_act)

        self.help_menu = menu.addMenu("")
        self.about_act = QAction("", self)
        self.about_act.triggered.connect(self.show_about)
        self.help_menu.addAction(self.about_act)

    def _retranslate(self) -> None:
        self.status.showMessage(tr(self.lang, "ready"))
        self.file_menu.setTitle(tr(self.lang, "file_menu"))
        self.open_act.setText(tr(self.lang, "open"))
        self.pack_act.setText(tr(self.lang, "pack"))
        self.unpack_act.setText(tr(self.lang, "unpack"))
        self.decoy_act.setText(tr(self.lang, "create_decoy"))
        self.sweep_act.setText(tr(self.lang, "sweep_decoys"))
        self.exit_act.setText(tr(self.lang, "exit"))
        self.lang_menu.setTitle(tr(self.lang, "language_menu"))
        self.lang_en_act.setText(tr(self.lang, "lang_en"))
        self.lang_ru_act.setText(tr(self.lang, "lang_ru"))
        self.help_menu.setTitle(tr(self.lang, "help_menu"))
        self.about_act.setText(tr(self.lang, "about"))

    def set_language(self, lang: str) -> None:
        if lang in LANGUAGES:
            self.lang = lang
            self._retranslate()

    def open_container(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            tr(self.lang, "select_container"),
            "",
            tr(self.lang, "file_filter"),
        )
        if not path:
            return

        try:
            meta = get_metadata(Path(path))
            pretty = json.dumps(meta, ensure_ascii=False, indent=2)
            self.editor.setPlainText(pretty)
            self.status.showMessage(tr(self.lang, "opened").format(name=Path(path).name))
        except Exception as e:
            QMessageBox.critical(self, tr(self.lang, "about_title"), tr(self.lang, "open_error").format(err=e))
            self.status.showMessage(tr(self.lang, "open_error").format(err=e))

    def pack_file_gui(self) -> None:
        src, _ = QFileDialog.getOpenFileName(self, tr(self.lang, "select_file"))
        if not src:
            return
        dst, _ = QFileDialog.getSaveFileName(
            self,
            tr(self.lang, "save_container"),
            Path(src).with_suffix(".zil").as_posix(),
            tr(self.lang, "file_filter"),
        )
        if not dst:
            return
        key_hex, ok = QInputDialog.getText(self, tr(self.lang, "key_title"), tr(self.lang, "key_prompt"))
        if not ok:
            return
        try:
            key = bytes.fromhex(key_hex.strip())
            pack_file(Path(src), Path(dst), key)
            self.status.showMessage(tr(self.lang, "pack_success").format(name=Path(dst).name))
            logger.info("packed %s", dst)
        except Exception as e:
            QMessageBox.critical(self, tr(self.lang, "error"), str(e))
            self.status.showMessage(str(e))

    def unpack_file_gui(self) -> None:
        src, _ = QFileDialog.getOpenFileName(self, tr(self.lang, "select_container"), "", tr(self.lang, "file_filter"))
        if not src:
            return
        dst, _ = QFileDialog.getSaveFileName(self, tr(self.lang, "save_file"), Path(src).with_suffix("").as_posix())
        if not dst:
            return
        key_hex, ok = QInputDialog.getText(self, tr(self.lang, "key_title"), tr(self.lang, "key_prompt"))
        if not ok:
            return
        try:
            key = bytes.fromhex(key_hex.strip())
            unpack_file(Path(src), Path(dst), key)
            self.status.showMessage(tr(self.lang, "unpack_success").format(name=Path(dst).name))
            logger.info("unpacked %s", src)
        except Exception as e:
            QMessageBox.critical(self, tr(self.lang, "error"), str(e))
            self.status.showMessage(str(e))

    def create_decoy_gui(self) -> None:
        dst, _ = QFileDialog.getSaveFileName(
            self,
            tr(self.lang, "save_container"),
            "decoy.zil",
            tr(self.lang, "file_filter"),
        )
        if not dst:
            return
        try:
            decoy.generate_decoy_file(Path(dst))
            self.status.showMessage(tr(self.lang, "decoy_created").format(name=Path(dst).name))
            logger.info("decoy created %s", dst)
        except Exception as e:
            QMessageBox.critical(self, tr(self.lang, "error"), str(e))
            self.status.showMessage(str(e))

    def sweep_decoys_gui(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, tr(self.lang, "select_folder"))
        if not folder:
            return
        try:
            removed = decoy.sweep_expired_decoys(Path(folder))
            self.status.showMessage(tr(self.lang, "decoy_sweep_done").format(num=removed))
            logger.info("decoy sweep %s -> %d", folder, removed)
        except Exception as e:
            QMessageBox.critical(self, tr(self.lang, "error"), str(e))
            self.status.showMessage(str(e))

    def show_about(self) -> None:
        QMessageBox.information(
            self,
            tr(self.lang, "about_title"),
            tr(self.lang, "about_message"),
        )


def main() -> None:
    lang = os.environ.get("UYUBOX_LANG", "en")
    if len(sys.argv) > 1 and sys.argv[1] in LANGUAGES:
        lang = sys.argv[1]
    app = QApplication(sys.argv)
    window = MainWindow(lang)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
