# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import importlib
import pytest

# Загружаем сам модуль unpack, чтобы патчить его переменные
unpack_mod = importlib.import_module(
    "zilant_prime_core.container.unpack"
)  # модуль с decrypt_aead :contentReference[oaicite:0]{index=0}
from zilant_prime_core.container.metadata import serialize_metadata
from zilant_prime_core.container.pack import pack
from zilant_prime_core.container.unpack import UnpackError, unpack
from zilant_prime_core.crypto.aead import DEFAULT_NONCE_LENGTH
from zilant_prime_core.crypto.kdf import DEFAULT_SALT_LENGTH


@pytest.fixture
def container_bytes(tmp_path):
    # создаём временный файл и упаковываем его
    src = tmp_path / "foo.bin"
    src.write_bytes(b"hello-world")
    # pack() принимает Path
    return pack(src, password="secret")


def test_unpack_missing_metadata_fields(tmp_path, container_bytes):
    raw = container_bytes
    orig_len = int.from_bytes(raw[0:4], "big")
    tail = raw[4 + orig_len :]  # salt+nonce+ct+tag
    # вместо метаданных — пустой JSON
    new_meta = b"{}"
    new_len = len(new_meta).to_bytes(4, "big")
    tampered = new_len + new_meta + tail

    with pytest.raises(UnpackError) as exc:
        unpack(tampered, tmp_path, password="secret")
    # при изменении meta_blob тег аутентификации не пройдёт
    assert "Неверная метка аутентификации" in str(exc.value)


def test_unpack_invalid_tag_raises_unpack_error(tmp_path, container_bytes):
    # ломаем последний байт, чтобы тег стал неверным
    tampered = bytearray(container_bytes)
    tampered[-1] ^= 0xFF

    with pytest.raises(UnpackError) as exc:
        unpack(bytes(tampered), tmp_path, password="secret")
    assert "Неверная метка аутентификации" in str(exc.value)


def test_unpack_incorrect_metadata_fields(monkeypatch, tmp_path):
    # готовим контейнер с валидным тегом, но «нестандартными» полями meta
    fake_meta = serialize_metadata({"foo": "bar"})
    salt = b"\x00" * DEFAULT_SALT_LENGTH
    nonce = b"\x00" * DEFAULT_NONCE_LENGTH
    payload = b"payload_data"
    # fake ciphertext+tag: payload + 16 нулей (минимальный размер для аутhtag)
    ct_tag = payload + b"\x00" * 16
    container = len(fake_meta).to_bytes(4, "big") + fake_meta + salt + nonce + ct_tag

    # Перехватываем внутри unpack вызов decrypt_aead и возвращаем наш payload
    monkeypatch.setattr(
        unpack_mod,
        "decrypt_aead",
        lambda key, nonce_arg, ct_tag_arg, aad: payload,
    )

    # Теперь unpack дойдёт до разбора filename/size и упадёт на «foo»/None
    with pytest.raises(UnpackError) as exc:
        unpack(container, tmp_path, password="secret")
    assert "Некорректные поля метаданных" in str(exc.value)
