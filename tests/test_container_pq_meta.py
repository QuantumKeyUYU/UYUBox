# tests/test_container_pq_meta.py
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import json

import container  # src/container.py


def test_pack_file_pq_meta_defaults(tmp_path, monkeypatch):
    # Подмена PQAEAD в container, чтобы обойти относительные импорты в aead.py
    class FakePQ:
        _NONCE_LEN = 2

        @staticmethod
        def encrypt(pub, plaintext, aad):
            # создаём «nonce» + payload
            return b"\xaa\xbb" + plaintext

    monkeypatch.setattr(container, "PQAEAD", FakePQ, raising=True)

    # Подготавливаем входной файл
    src = tmp_path / "in.txt"
    src.write_text("hello-pq")
    cont = tmp_path / "out.zil"
    key = b"k" * 32

    # Вызываем pack_file в PQ-режиме с extra_meta
    container.pack_file(src, cont, key, pq_public_key=b"pubkey", extra_meta={"foo": "bar"})

    # Разбираем контейнер: header и payload
    data = cont.read_bytes()
    header_bytes, payload = data.split(b"\n\n", 1)
    meta = json.loads(header_bytes.decode("utf-8"))

    # Проверяем поля meta_pq
    assert meta["mode"] == "pq"
    assert meta["foo"] == "bar"
    assert meta["heal_level"] == 0
    assert isinstance(meta["heal_history"], list)

    # payload начинается с нашего «nonce» и содержит оригинальные данные
    assert payload.startswith(b"\xaa\xbb")
    assert payload.endswith(src.read_bytes())
