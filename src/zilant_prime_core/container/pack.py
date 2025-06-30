# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

__all__ = [
    "PackError",
    "pack",
]

# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import json
import os
from pathlib import Path

from zilant_prime_core.crypto.aead import encrypt_aead
from zilant_prime_core.crypto.kdf import derive_key
from zilant_prime_core.utils.constants import DEFAULT_NONCE_LENGTH, DEFAULT_SALT_LENGTH


class PackError(Exception):
    """Ошибка при упаковке контейнера."""

    pass


def pack(src_path: Path, password: str) -> bytes:
    """
    Упаковывает файл src_path в байтовый контейнер:
      [4-bytes meta_len][meta_json][salt][nonce][ciphertext||tag]
    где meta_json содержит {"filename": ..., "size": ...}.
    """
    # 1) Считываем payload
    data = src_path.read_bytes()

    # 2) Формируем метаданные
    meta = {"filename": src_path.name, "size": len(data)}
    meta_bytes = json.dumps(meta).encode("utf-8")
    meta_len = len(meta_bytes).to_bytes(4, "big")

    # 3) Генерируем соль и ключ
    salt = os.urandom(DEFAULT_SALT_LENGTH)
    key = derive_key(password.encode("utf-8"), salt)

    # 4) Генерируем nonce и шифруем (ciphertext||tag)
    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    ct_and_tag = encrypt_aead(key, nonce, data, aad=meta_bytes)

    # 5) Собираем контейнер
    return meta_len + meta_bytes + salt + nonce + ct_and_tag
