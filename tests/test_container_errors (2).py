# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from zilant_prime_core.container.unpack import UnpackError, unpack


def test_unpack_file_bad_meta(tmp_path):
    # Создаём некорректный контейнер: невалидные метаданные
    file = tmp_path / "bad.zil"
    file.write_bytes(b"\x00\x00\x00\x05xxxxxrest")
    # Ожидаем именно UnpackError
    with pytest.raises(UnpackError):
        unpack(file, tmp_path, "password")
