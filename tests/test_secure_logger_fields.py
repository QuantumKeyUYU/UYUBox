# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import secrets

from zilant_prime_core.utils.secure_logging import SecureLogger


class DummyObj:
    def __str__(self):
        return "<DummyObj: str-representation>"


def test_secure_logger_fields_to_str(tmp_path):
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "fields.log")
    slog = SecureLogger(key=key, log_path=log_file)

    # Передаем разные типы дополнительных полей
    slog.log(
        "Message",
        "LEVEL",
        foo=42,  # int
        bar=None,  # None
        arr=[1, 2, 3],  # list, будет str()
        obj=DummyObj(),  # custom object, будет str()
    )
    entries = slog.read_logs()

    # Ищем трёхэлементный кортеж (level, msg, fields)
    assert any(
        tup[0] == "LEVEL" and tup[1] == "Message" and isinstance(tup[2], dict) for tup in entries if len(tup) == 3
    )

    # Проверяем типы
    for tup in entries:
        if len(tup) == 3 and tup[0] == "LEVEL" and tup[1] == "Message":
            fields = tup[2]
            assert fields["foo"] == 42
            assert fields["bar"] is None
            assert isinstance(fields["arr"], str)  # список превращён в строку
            assert fields["arr"] == "[1, 2, 3]"
            assert isinstance(fields["obj"], str)
            assert fields["obj"] == "<DummyObj: str-representation>"
