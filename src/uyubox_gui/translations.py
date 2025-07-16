# SPDX-License-Identifier: MIT

"""Simple translation helpers for UYUBox GUI."""

from __future__ import annotations

from typing import Dict

LANGUAGES = ["en", "ru"]

_STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "file_menu": "&File",
        "open": "Open container…",
        "pack": "Pack file…",
        "unpack": "Unpack container…",
        "create_decoy": "Create decoy…",
        "sweep_decoys": "Sweep decoys…",
        "exit": "Exit",
        "help_menu": "&Help",
        "about": "About",
        "select_container": "Select .zil container",
        "file_filter": "UYUBox containers (*.zil);;All files (*)",
        "opened": "Opened {name}",
        "pack_success": "Packed to {name}",
        "unpack_success": "Unpacked to {name}",
        "decoy_created": "Created decoy {name}",
        "decoy_sweep_done": "Removed {num} decoy files",
        "open_error": "Could not read metadata:\n{err}",
        "ready": "Ready",
        "about_message": "UYUBox v0.9.9b2\n© 2025 Zilant Prime Core contributors",
        "about_title": "About UYUBox",
        "language_menu": "&Language",
        "lang_en": "English",
        "lang_ru": "Russian",
        "select_file": "Select file",
        "save_container": "Save container",
        "save_file": "Save file",
        "select_folder": "Select folder",
        "key_title": "Encryption key",
        "key_prompt": "Enter 32-byte key as hex",
        "error": "Error",
    },
    "ru": {
        "file_menu": "&Файл",
        "open": "Открыть контейнер…",
        "pack": "Запаковать файл…",
        "unpack": "Распаковать контейнер…",
        "create_decoy": "Создать decoy…",
        "sweep_decoys": "Очистить decoy…",
        "exit": "Выход",
        "help_menu": "&Справка",
        "about": "О программе",
        "select_container": "Выберите .zil-файл контейнера",
        "file_filter": "UYUBox containers (*.zil);;Все файлы (*)",
        "opened": "Открыт {name}",
        "pack_success": "Упаковано в {name}",
        "unpack_success": "Распаковано в {name}",
        "decoy_created": "Создан decoy {name}",
        "decoy_sweep_done": "Удалено decoy-файлов: {num}",
        "open_error": "Не удалось прочитать метаданные:\n{err}",
        "ready": "Готово",
        "about_message": "UYUBox v0.9.9b2\n© 2025 Zilant Prime Core contributors",
        "about_title": "О программе UYUBox",
        "language_menu": "&Язык",
        "lang_en": "Английский",
        "lang_ru": "Русский",
        "select_file": "Выберите файл",
        "save_container": "Сохранить контейнер",
        "save_file": "Сохранить файл",
        "select_folder": "Выберите папку",
        "key_title": "Ключ шифрования",
        "key_prompt": "Введите 32-байтный ключ в hex",
        "error": "Ошибка",
    },
}


def tr(lang: str, key: str) -> str:
    """Return translated text for *key* in *lang*."""
    return _STRINGS.get(lang, _STRINGS["en"]).get(key, key)
