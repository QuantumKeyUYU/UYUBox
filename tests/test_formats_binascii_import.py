# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_formats_binascii_import.py

import importlib

mod = importlib.import_module("src.zilant_prime_core.utils.formats")
# Убедимся, что модуль загрузился без ошибок
assert hasattr(mod, "to_hex") and hasattr(mod, "from_hex")
