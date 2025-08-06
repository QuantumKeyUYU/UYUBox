from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from argon2.low_level import hash_secret_raw, Type  # type: ignore
from kivy.clock import Clock, mainthread
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.utils import platform
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.filemanager import MDFileManager
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.toolbar import MDToolbar

# Импортируем функции упаковки и распаковки из zilant-prime-core.
try:
    from zilant_prime_core.container import pack_file, unpack_file  # type: ignore
except ImportError:
    pack_file = None  # type: ignore
    unpack_file = None  # type: ignore


def derive_key(password: str, salt: bytes, time_cost: int = 3, memory_cost: int = 32768) -> bytes:
    """Derive a 32‑byte encryption key from a password and salt using Argon2id."""
    if not password:
        raise ValueError("Password must not be empty")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )


def read_metadata(container_path: str) -> Dict[str, Any]:
    """Extract JSON metadata from a `.zil` container without decrypting payload."""
    data = Path(container_path).read_bytes()
    sep = b"\n\n"
    idx = data.find(sep)
    if idx == -1:
        raise ValueError("Invalid container format: missing header separator")
    header_bytes = data[:idx]
    try:
        meta: Dict[str, Any] = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Cannot parse metadata: {exc}")
    return meta


class ZilantMobileApp(MDApp):
    """Основной класс приложения Zilant Prime Mobile."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.file_manager: Optional[MDFileManager] = None
        self.current_action: Optional[str] = None
        self.selected_path: Optional[str] = None
        self.dialog: Optional[MDDialog] = None

    def build(self) -> MDBoxLayout:
        """Собирает интерфейс приложения и запрашивает права."""
        self.title = "Zilant Mobile"
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.primary_hue = "500"

        # ❗️❗️❗️ ВОТ ОНО, ФИНАЛЬНОЕ ИСПРАВЛЕНИЕ ❗️❗️❗️
        # При запуске на Android, запрашиваем права на доступ к файлам.
        if platform == "android":
            from android.permissions import request_permissions, Permission
            permissions_to_request = [
                Permission.READ_EXTERNAL_STORAGE,
                Permission.WRITE_EXTERNAL_STORAGE
            ]
            request_permissions(permissions_to_request)
        # ❗️❗️❗️ КОНЕЦ ИСПРАВЛЕНИЯ ❗️❗️❗️

        root = MDBoxLayout(orientation="vertical")
        toolbar = MDToolbar(title="Zilant Mobile")
        toolbar.pos_hint = {"top": 1}
        root.add_widget(toolbar)

        buttons_box = MDBoxLayout(orientation="vertical", spacing=dp(20), padding=dp(40))
        buttons_box.add_widget(MDRaisedButton(text="Упаковать файл", pos_hint={"center_x": 0.5}, on_release=lambda _: self.start_action("pack")))
        buttons_box.add_widget(MDRaisedButton(text="Распаковать файл", pos_hint={"center_x": 0.5}, on_release=lambda _: self.start_action("unpack")))
        buttons_box.add_widget(MDRaisedButton(text="Метаданные контейнера", pos_hint={"center_x": 0.5}, on_release=lambda _: self.start_action("meta")))
        root.add_widget(buttons_box)

        return root

    def start_action(self, action: str) -> None:
        """Инициализирует выбранное действие и запускает файловый менеджер."""
        self.current_action = action
        if not self.file_manager:
            self.file_manager = MDFileManager(
                select_path=self._on_file_selected,
                exit_manager=self._on_file_manager_close,
                preview=False,
            )
        start_dir = os.path.expanduser("~")
        # Для Android нужно получить доступ к основному хранилищу
        if platform == "android":
            from android.storage import primary_external_storage_path
            start_dir = primary_external_storage_path()
            
        self.file_manager.show(start_dir)

    def _on_file_manager_close(self, *args: Any) -> None:
        """Закрывает файловый менеджер."""
        if self.file_manager:
            self.file_manager.close()

    def _on_file_selected(self, path: str) -> None:
        """Вызывается при выборе файла в файловом менеджере."""
        self.selected_path = path
        self._on_file_manager_close()
        if self.current_action == "pack":
            self._show_pack_dialog()
        elif self.current_action == "unpack":
            self._show_unpack_dialog()
        elif self.current_action == "meta":
            self._show_meta_dialog()

    def _show_pack_dialog(self) -> None:
        """Отображает диалог для ввода пароля и имени выходного контейнера."""
        box = MDBoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10), size_hint_y=None, height=dp(150))
        pwd_field = MDTextField(hint_text="Пароль", password=True)
        out_name_field = MDTextField(hint_text="Имя контейнера (.zil)", text=f"{Path(self.selected_path).name}.zil")
        box.add_widget(pwd_field)
        box.add_widget(out_name_field)
        self.dialog = MDDialog(
            title="Упаковка файла", type="custom", content_cls=box,
            buttons=[
                MDFlatButton(text="Отмена", on_release=lambda _: self.dialog.dismiss()),
                MDFlatButton(text="Упаковать", on_release=lambda _: self._thread_pack(pwd_field.text, out_name_field.text)),
            ],
        )
        self.dialog.open()

    def _thread_pack(self, password: str, output_name: str) -> None:
        """Запускает упаковку в отдельном потоке."""
        if self.dialog: self.dialog.dismiss()
        threading.Thread(target=self.do_pack, args=(password, output_name)).start()

    def do_pack(self, password: str, output_name: str) -> None:
        """Выполняет упаковку файла в .zil контейнер."""
        if pack_file is None:
            self._show_message("Модуль zilant-prime-core не найден.")
            return
        try:
            if not password: raise ValueError("Пароль не должен быть пустым")
            if not output_name: raise ValueError("Укажите имя выходного файла")
            salt = os.urandom(16)
            key = derive_key(password, salt)
            in_path = Path(self.selected_path)
            out_name = output_name if output_name.endswith(".zil") else f"{output_name}.zil"
            out_path = in_path.parent / out_name
            meta = {"salt_hex": salt.hex(), "filename": in_path.name}
            pack_file(in_path, out_path, key, extra_meta=meta)
            self._show_message(f"Упаковано: {out_path}")
        except Exception as exc:
            self._show_message(f"Ошибка упаковки: {exc}")

    def _show_unpack_dialog(self) -> None:
        """Отображает диалог для ввода пароля при распаковке."""
        try:
            meta = read_metadata(self.selected_path)
            default_name = meta.get("filename", Path(self.selected_path).stem)
        except Exception:
            default_name = Path(self.selected_path).stem + "_out"

        box = MDBoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10), size_hint_y=None, height=dp(150))
        pwd_field = MDTextField(hint_text="Пароль", password=True)
        out_name_field = MDTextField(hint_text="Имя выходного файла", text=default_name)
        box.add_widget(pwd_field)
        box.add_widget(out_name_field)
        self.dialog = MDDialog(
            title="Распаковка файла", type="custom", content_cls=box,
            buttons=[
                MDFlatButton(text="Отмена", on_release=lambda _: self.dialog.dismiss()),
                MDFlatButton(text="Распаковать", on_release=lambda _: self._thread_unpack(pwd_field.text, out_name_field.text)),
            ],
        )
        self.dialog.open()

    def _thread_unpack(self, password: str, output_name: str) -> None:
        if self.dialog: self.dialog.dismiss()
        threading.Thread(target=self.do_unpack, args=(password, output_name)).start()

    def do_unpack(self, password: str, output_name: str) -> None:
        """Выполняет распаковку контейнера."""
        if unpack_file is None:
            self._show_message("Модуль zilant-prime-core не найден.")
            return
        try:
            if not password: raise ValueError("Пароль не должен быть пустым")
            meta = read_metadata(self.selected_path)
            salt = bytes.fromhex(meta.get("salt_hex", ""))
            if not salt: raise ValueError("Контейнер не содержит соль.")
            key = derive_key(password, salt)
            in_path = Path(self.selected_path)
            out_name = output_name or meta.get("filename", in_path.stem)
            out_path = in_path.parent / out_name
            unpack_file(in_path, out_path, key)
            self._show_message(f"Распаковано: {out_path}")
        except Exception as exc:
            self._show_message(f"Ошибка распаковки: {exc}")

    def _show_meta_dialog(self) -> None:
        """Отображает метаданные контейнера."""
        try:
            meta = read_metadata(self.selected_path)
            meta_text = json.dumps(meta, ensure_ascii=False, indent=2)
        except Exception as exc:
            meta_text = f"Невозможно прочитать метаданные: {exc}"

        self.dialog = MDDialog(
            title="Метаданные контейнера", text=meta_text,
            buttons=[MDFlatButton(text="OK", on_release=lambda _: self.dialog.dismiss())],
        )
        self.dialog.open()

    @mainthread
    def _show_message(self, message: str) -> None:
        """Показывает всплывающее окно с сообщением."""
        if self.dialog:
            self.dialog.dismiss()
        self.dialog = MDDialog(
            title="Сообщение", text=message,
            buttons=[MDFlatButton(text="OK", on_release=lambda _: self.dialog.dismiss())],
        )
        self.dialog.open()

if __name__ == "__main__":
    ZilantMobileApp().run()