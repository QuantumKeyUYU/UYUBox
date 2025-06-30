# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import json
import pytest

from zilant_prime_core.container.metadata import MetadataError, deserialize_metadata, serialize_metadata


def test_serialize_nested_bytes_dict():
    # Вложенный dict с bytes → должен рекурсивно закодировать в base64
    meta = {"nested": {"foo": b"\x01\x02"}}
    raw = serialize_metadata(meta)
    # Декодируем из JSON и проверяем
    decoded = deserialize_metadata(raw)
    assert decoded == {"nested": {"foo": "AQI="}}


def test_serialize_bytes_in_list_and_tuple():
    # Список и кортеж с элементами bytes → байты внутри списка кодируются, кортеж становится списком
    meta = {
        "lst": [b"ab", "c", 1],
        "tup": (b"d", 2),
    }
    raw = serialize_metadata(meta)
    decoded = json.loads(raw.decode("utf-8"))
    # JSON всегда отдаёт массивы как list
    assert decoded["lst"] == ["YWI=", "c", 1]
    # Для 'd' байт получаем 'ZA==' с двойным паддингом
    assert decoded["tup"] == ["ZA==", 2]


def test_serialize_invalid_type_raises():
    # Неподдерживаемый тип вместо Mapping/Metadata → MetadataError
    with pytest.raises(MetadataError) as exc:
        serialize_metadata(123)
    assert "meta must be Mapping or Metadata" in str(exc.value)
