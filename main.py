import os
import sys
from kivy.lang import Builder
from kivy.core.window import Window
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.filechooser import FileChooserIconView
from kivymd.app import MDApp
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.label import MDLabel

# Не грузим тяжёлые части ядра заранее
try:
    from zilant_prime_core.crypto import derive_key
    from zilant_prime_core.container import read_metadata
except Exception as e:
    derive_key = None
    read_metadata = None
    print(f"[WARN] ядро (crypto/container) не загрузилось на старте: {e}")

class FileChooserScreen(Screen):
    pass

class MainScreen(Screen):
    def do_pack(self, password: str, output_name: str) -> None:
        try:
            from zilant_prime_core.container import pack_file
        except Exception as e:
            self._show_message(f"Ошибка загрузки ядра: {e}")
            return
        try:
            pack_file(self.ids.file_path.text, password, output_name)
            self._show_message("Файл успешно упакован.")
        except Exception as e:
            self._show_message(f"Ошибка упаковки: {e}")

    def do_unpack(self, password: str, output_name: str) -> None:
        try:
            from zilant_prime_core.container import unpack_file
        except Exception as e:
            self._show_message(f"Ошибка загрузки ядра: {e}")
            return
        try:
            unpack_file(self.ids.file_path.text, password, output_name)
            self._show_message("Файл успешно распакован.")
        except Exception as e:
            self._show_message(f"Ошибка распаковки: {e}")

    def show_metadata(self) -> None:
        if not read_metadata:
            self._show_message("Функция недоступна: ядро не загружено.")
            return
        try:
            meta = read_metadata(self.ids.file_path.text)
            self._show_message(f"Метаданные:\n{meta}")
        except Exception as e:
            self._show_message(f"Ошибка чтения метаданных: {e}")

    def _show_message(self, text: str) -> None:
        dialog = MDDialog(
            title="Сообщение",
            text=text,
            buttons=[MDRaisedButton(text="OK", on_release=lambda x: dialog.dismiss())]
        )
        dialog.open()

class ZilantPrimeApp(MDApp):
    def build(self):
        self.title = "Zilant Prime Mobile"
        Window.size = (360, 640)
        sm = ScreenManager()
        sm.add_widget(MainScreen(name="main"))
        sm.add_widget(FileChooserScreen(name="filechooser"))
        return sm

if __name__ == "__main__":
    # Разрешения на устройстве
    try:
        from android.permissions import request_permissions, Permission
        request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
    except Exception:
        pass

    ZilantPrimeApp().run()
