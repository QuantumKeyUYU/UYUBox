"""Entry point for the UYUBox Quantum mobile client."""
from __future__ import annotations

import os

from kivy.core.window import Window
from kivy.lang import Builder
from kivy.utils import platform
from kivymd.app import MDApp

# Ensure packages are discoverable when running via buildozer or desktop python.
os.environ.setdefault("KIVY_GL_BACKEND", "angle_sdl2")


class UYUBoxApp(MDApp):
    def build(self):  # type: ignore[override]
        self.title = "UYUBox Quantum"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "BlueGray"
        if platform in {"linux", "win", "macosx"}:
            Window.size = (420, 860)
        return Builder.load_file("ui/main.kv")

    def on_start(self) -> None:
        super().on_start()
        try:
            from android.permissions import Permission, request_permissions

            request_permissions(
                [Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE]
            )
        except Exception:
            pass


if __name__ == "__main__":
    UYUBoxApp().run()
