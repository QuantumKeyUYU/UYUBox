"""
Zilant Prime Mobile Application
------------------------------

Это минималистичное Android‑приложение на базе Kivy MD, которое оборачивает
функции из `zilant-prime-core` и позволяет пользователю безопасно упаковывать
и распаковывать файлы в `.zil` контейнеры. Приложение использует
Argon2id для derivирования ключа из пользовательского пароля и сохраняет
случайную соль в мета‑информации контейнера. Благодаря этому файл может быть
расшифрован только при наличии правильного пароля и соответствующего salt.
"""

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

# Импортируем функции упаковки и распаковки из zilant-prime-core. При
# сборке APK эти модули попадут в приложение через requirements в buildozer.spec.
try:
    from zilant_prime_core.container import pack_file, unpack_file  # type: ignore
except ImportError:
    # Для случаев, когда пакет не установлен (например, разработка без
    # установки зависимостей), вы можете установить его командой
    # `pip install -r requirements.txt`.
    pack_file = None  # type: ignore
    unpack_file = None  # type: ignore


def derive_key(password: str, salt: bytes, time_cost: int = 3, memory_cost: int = 32768) -> bytes:
    """Derive a 32‑byte encryption key from a password and salt using Argon2id.

    Args:
        password: Пароль пользователя в виде строки.
        salt: Случайные байты длиной 16 байт, сохранённые в метаданных контейнера.
        time_cost: Количество проходов алгоритма; увеличение повышает стойкость.
        memory_cost: Объём используемой памяти в KiB. Для мобильных устройств
            значение около 32–64 МиБ обеспечивает баланс между скоростью и безопасностью.

    Returns:
        32‑байтовый ключ, готовый для передачи в pack_file/unpack_file.
    """
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
    """Extract JSON metadata from a `.zil` container without decrypting payload.

    The container format used in zilant-prime-core stores a JSON object
    at the beginning of the file, followed by a blank line and the ciphertext.

    Args:
        container_path: Путь к контейнеру `.zil`.

    Returns:
        Словарь с метаданными контейнера.

    Raises:
        ValueError: если файл не содержит ожидаемый разделитель или JSON‑заголовок.
    """
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
        self.current_action: Optional[str] = None  # 'pack', 'unpack', 'meta'
        self.selected_path: Optional[str] = None
        self.dialog: Optional[MDDialog] = None

    def build(self) -> MDBoxLayout:
        """Собирает интерфейс приложения."""
        self.title = "Zilant Mobile"
        # Настройка темы: светлая тема с голубым акцентом
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.primary_hue = "500"

        root = MDBoxLayout(orientation="vertical")

        # Верхняя панель (toolbar)
        toolbar = MDToolbar(title="Zilant Mobile")
        toolbar.pos_hint = {"top": 1}
        root.add_widget(toolbar)

        # Основные кнопки
        btn_pack = MDRaisedButton(
            text="Упаковать файл",
            pos_hint={"center_x": 0.5},
            on_release=lambda _: self.start_action("pack"),
        )
        btn_unpack = MDRaisedButton(
            text="Распаковать файл",
            pos_hint={"center_x": 0.5},
            on_release=lambda _: self.start_action("unpack"),
        )
        btn_meta = MDRaisedButton(
            text="Метаданные контейнера",
            pos_hint={"center_x": 0.5},
            on_release=lambda _: self.start_action("meta"),
        )

        # Контейнер для кнопок
        buttons_box = MDBoxLayout(
            orientation="vertical",
            spacing=dp(20),
            padding=dp(40),
        )
        buttons_box.add_widget(btn_pack)
        buttons_box.add_widget(btn_unpack)
        buttons_box.add_widget(btn_meta)

        root.add_widget(buttons_box)
        return root

    def start_action(self, action: str) -> None:
        """Инициализирует выбранное действие и запускает файловый менеджер."""
        self.current_action = action
        # Создаём менеджер при первом использовании, чтобы избежать утечки
        self.file_manager = MDFileManager(
            select_path=self._on_file_selected,
            exit_manager=self._on_file_manager_close,
            preview=False,
        )
        # В Android root '/' пуст — безопаснее начинать с домашней директории
        start_dir = os.path.expanduser("~")
        self.file_manager.show(start_dir)

    def _on_file_manager_close(self, *args: Any) -> None:
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
        # Контент диалога
        box = MDBoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10))
        pwd_field = MDTextField(
            hint_text="Пароль",
            password=True,
            helper_text="Введите пароль для шифрования",
            helper_text_mode="on_focus",
        )
        out_name_field = MDTextField(
            hint_text="Имя контейнера (.zil)",
            text=f"{Path(self.selected_path).name}.zil",
            helper_text="Введите имя файла контейнера",
            helper_text_mode="on_focus",
        )
        box.add_widget(pwd_field)
        box.add_widget(out_name_field)

        self.dialog = MDDialog(
            title="Упаковка файла",
            type="custom",
            content_cls=box,
            buttons=[
                MDFlatButton(text="Отмена", on_release=lambda _: self.dialog.dismiss()),
                MDFlatButton(
                    text="Упаковать",
                    on_release=lambda _: self._thread_pack(pwd_field.text, out_name_field.text),
                ),
            ],
        )
        self.dialog.open()

    def _thread_pack(self, password: str, output_name: str) -> None:
        """Запускает упаковку в отдельном потоке."""
        self.dialog.dismiss()
        thread = threading.Thread(target=self.do_pack, args=(password, output_name))
        thread.start()

    def do_pack(self, password: str, output_name: str) -> None:
        """Выполняет упаковку файла в .zil контейнер."""
        if pack_file is None:
            self._show_message("Модуль zilant-prime-core не найден. Установите зависимости.")
            return
        try:
            if not password:
                raise ValueError("Пароль не должен быть пустым")
            if not output_name:
                raise ValueError("Укажите имя выходного файла")
            salt = os.urandom(16)
            key = derive_key(password, salt)
            in_path = Path(self.selected_path)
            # Если пользователь не добавил .zil, добавляем автоматически
            out_name = output_name if output_name.endswith(".zil") else f"{output_name}.zil"
            out_path = in_path.parent / out_name
            meta = {
                "salt_hex": salt.hex(),
                "filename": in_path.name,
            }
            pack_file(in_path, out_path, key, extra_meta=meta)  # type: ignore
            self._show_message(f"Упаковано: {out_path}")
        except Exception as exc:
            self._show_message(f"Ошибка упаковки: {exc}")

    def _show_unpack_dialog(self) -> None:
        """Отображает диалог для ввода пароля и имени выходного файла при распаковке."""
        try:
            meta = read_metadata(self.selected_path)  # type: ignore[arg-type]
            default_name = meta.get("filename", Path(self.selected_path).stem)
        except Exception:
            default_name = Path(self.selected_path).stem + "_out"

        box = MDBoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10))
        pwd_field = MDTextField(
            hint_text="Пароль",
            password=True,
            helper_text="Введите пароль для расшифровки",
            helper_text_mode="on_focus",
        )
        out_name_field = MDTextField(
            hint_text="Имя выходного файла",
            text=default_name,
            helper_text="Можно изменить имя файла, куда будет сохранён результат",
            helper_text_mode="on_focus",
        )
        box.add_widget(pwd_field)
        box.add_widget(out_name_field)
        self.dialog = MDDialog(
            title="Распаковка файла",
            type="custom",
            content_cls=box,
            buttons=[
                MDFlatButton(text="Отмена", on_release=lambda _: self.dialog.dismiss()),
                MDFlatButton(
                    text="Распаковать",
                    on_release=lambda _: self._thread_unpack(pwd_field.text, out_name_field.text),
                ),
            ],
        )
        self.dialog.open()

    def _thread_unpack(self, password: str, output_name: str) -> None:
        self.dialog.dismiss()
        thread = threading.Thread(target=self.do_unpack, args=(password, output_name))
        thread.start()

    def do_unpack(self, password: str, output_name: str) -> None:
        """Выполняет распаковку контейнера."""
        if unpack_file is None:
            self._show_message("Модуль zilant-prime-core не найден. Установите зависимости.")
            return
        try:
            if not password:
                raise ValueError("Пароль не должен быть пустым")
            meta = read_metadata(self.selected_path)  # type: ignore[arg-type]
            salt_hex = meta.get("salt_hex")
            if not salt_hex:
                raise ValueError("Контейнер не содержит соль. Невозможно derive ключ.")
            salt = bytes.fromhex(str(salt_hex))
            key = derive_key(password, salt)
            in_path = Path(self.selected_path)
            # Подставляем расширение из исходного имени, если пользователь не указал
            out_name = output_name
            if not out_name:
                out_name = meta.get("filename", in_path.stem)
            out_path = in_path.parent / out_name
            unpack_file(in_path, out_path, key)  # type: ignore
            self._show_message(f"Распаковано: {out_path}")
        except Exception as exc:
            self._show_message(f"Ошибка распаковки: {exc}")

    def _show_meta_dialog(self) -> None:
        """Отображает модальное окно с метаданными выбранного контейнера."""
        try:
            meta = read_metadata(self.selected_path)  # type: ignore[arg-type]
            meta_text = json.dumps(meta, ensure_ascii=False, indent=2)
        except Exception as exc:
            meta_text = f"Невозможно прочитать метаданные: {exc}"
        label = MDLabel(text=meta_text, theme_text_color="Primary", size_hint_y=None)
        label.height = dp(200)  # ограничиваем высоту текста
        self.dialog = MDDialog(
            title="Метаданные контейнера",
            type="custom",
            content_cls=MDBoxLayout(orientation="vertical", children=[label]),
            buttons=[MDFlatButton(text="OK", on_release=lambda _: self.dialog.dismiss())],
        )
        self.dialog.open()

    @mainthread
    def _show_message(self, message: str) -> None:
        """Показывает всплывающее модальное окно с сообщением."""
        dialog = MDDialog(
            title="Сообщение",
            text=message,
            buttons=[MDFlatButton(text="OK", on_release=lambda _: dialog.dismiss())],
        )
        dialog.open()


if __name__ == "__main__":
    ZilantMobileApp().run()