# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import secrets

from zilant_prime_core.utils.secure_logging import SecureLogger


def test_skip_line_without_separator(tmp_path):
    # 1) создаём логгер с пустым файлом
    log_file = str(tmp_path / "skip.log")
    slog = SecureLogger(key=secrets.token_bytes(32), log_path=log_file)

    # 2) вручную пишем «корявую» строку (нет разделителя `|`)
    with open(log_file, "ab") as f:
        f.write(b"this_is_not_valid_log_line\n")

    # 3) вызов read_logs() не должен падать, а должен вернуть пустой список
    assert slog.read_logs() == []


def test_tampered_line_restores(tmp_path):
    # После повреждения одной строки остальное продолжает читаться
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "tamper.log")
    slog = SecureLogger(key=key, log_path=log_file)

    # Запишем пару валидных записей
    slog.log("First entry", "INFO")
    slog.log("Second entry", "DEBUG")

    # Повреждаем вторую строку (дописав мусор)
    with open(log_file, "r+b") as f:
        lines = f.readlines()
        # портим вторую строку целиком
        f.seek(len(lines[0]))
        f.write(b"invalid|line\n")

    # Теперь slog.read_logs() должен вернуть только первую (валидную) запись
    entries = slog.read_logs()
    assert ("INFO", "First entry") in entries
    assert ("DEBUG", "Second entry") not in entries
