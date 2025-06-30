# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from zilant_prime_core.utils import counter as uc


def test_counter_read_write_increment(tmp_path, monkeypatch):
    main = tmp_path / "c"
    backup = tmp_path / "b"
    monkeypatch.setattr(uc, "COUNTER_FILE", main)
    monkeypatch.setattr(uc, "BACKUP_COUNTER_FILE", backup)
    assert uc.read_counter() == 0
    uc.write_counter(5)
    assert main.read_text() == "5"
    assert uc.read_counter() == 5
    uc.increment_counter()
    assert uc.read_counter() == 6


def test_write_counter_invalid(tmp_path, monkeypatch):
    monkeypatch.setattr(uc, "COUNTER_FILE", tmp_path / "c")
    monkeypatch.setattr(uc, "BACKUP_COUNTER_FILE", tmp_path / "b")
    with pytest.raises(ValueError):
        uc.write_counter(-1)


def test_read_counter_error(monkeypatch):
    class BadPath:
        def __init__(self, *args, **kwargs):
            # игнорируем входной путь
            pass

        def exists(self):
            # говорим, что файл "существует"
            return True

        def read_text(self):
            # имитируем ошибку при чтении
            raise OSError

    # подставляем наш "бракованный" путь вместо реальных файлов
    monkeypatch.setattr(uc, "COUNTER_FILE", BadPath("/tmp/x"))
    monkeypatch.setattr(uc, "BACKUP_COUNTER_FILE", BadPath("/tmp/y"))

    # несмотря на то что exists() == True, read_text() бросает OSError,
    # оба пути пропустятся, и в итоге вернётся 0
    assert uc.read_counter() == 0
