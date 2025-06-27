# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# demo_secure.py
from uyubox_core.utils import get_secure_logger

if __name__ == "__main__":
    slog = get_secure_logger("demo_secure.log")
    slog.log("Первое сообщение", "INFO")
    slog.log("Второе\nс переносом", "WARNING")
    print("Читаем защищённый лог:")
    for lvl, msg in slog.read_logs():
        print(lvl, msg)
