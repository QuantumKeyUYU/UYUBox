from __future__ import annotations

from pathlib import Path

from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen


class FileChooserScreen(MDScreen):
    def select(self, selection) -> None:
        if not selection:
            return
        app = MDApp.get_running_app()
        home = app.root.get_screen("home")
        path = str(Path(selection[0]))
        home.choose_file(path)
        app.root.current = "home"
