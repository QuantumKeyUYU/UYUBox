# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

__version__ = "0.9.9b2"

__all__ = ["__version__"]

import os
from typing import Mapping, cast  # Добавляем cast

from .cli import _abort  # NoReturn

# Проверка импорта перед инициализацией в CI
if os.environ.get("ZILANT_CI_IMPORT_HOOK"):
    _abort("Unsafe import before guard!", code=99)  # pragma: no cover

from .utils import root_guard

# Проверка, что не работает с root-правами, если не разрешено
if not os.environ.get("ZILANT_ALLOW_ROOT") and "PYTEST_CURRENT_TEST" not in os.environ:
    root_guard.assert_safe_or_die()  # pragma: no cover

# Укрепление безопасности для Linux
root_guard.harden_linux()

# Пример типизации для словаря (если необходимо для Mypy)
from types import SimpleNamespace
from typing import Any, Dict

# Пример, как использовать кастинг для соответствия типам
example_dict: Dict[str, str] = {"key": "value"}  # Обычный dict

# Преобразуем dict в Mapping для корректности с Mypy
example = SimpleNamespace(**cast(Mapping[str, Any], example_dict))  # Используем cast, чтобы привести к типу

# Приветствие и тестирование
# Hello, Zilant!
# ZILANT PRIME TEST 12345
