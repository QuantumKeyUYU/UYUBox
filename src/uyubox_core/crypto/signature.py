# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

__all__ = [
    "KEY_SIZE",
    "SIG_SIZE",
    "SignatureError",
    "generate_keypair",
    "sign",
    "verify",
]

# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import hashlib
import os


class SignatureError(Exception):
    """Ошибка при подписи или неверные ключи/подпись."""


# Размер приватного/публичного ключа и подписи
KEY_SIZE = 32
SIG_SIZE = hashlib.sha256().digest_size


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Генерирует ключевую пару (pub, priv).
    Для простоты pub == priv (только для тестов).
    """
    priv = os.urandom(KEY_SIZE)
    pub = priv
    return pub, priv


def sign(priv: bytes, msg: bytes) -> bytes:
    """
    Подписывает сообщение msg приватным ключом priv.
    При любых некорректных аргументах бросает SignatureError.
    """
    if not isinstance(priv, (bytes, bytearray)) or len(priv) != KEY_SIZE:
        raise SignatureError("Invalid private key.")
    if not isinstance(msg, (bytes, bytearray)):
        raise SignatureError("Invalid message.")
    return hashlib.sha256(priv + msg).digest()


def verify(pub: bytes, msg: bytes, sig: bytes, strict: bool = False) -> bool:
    """
    Проверяет подпись:
      - Если strict=False (режим по умолчанию), при некорректных аргументах возвращает False.
      - Если strict=True, при некорректных аргументах бросает SignatureError.
    Возвращает True, если сигнатура валидна, иначе False.
    """
    # Валидация аргументов
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != KEY_SIZE:
        if strict:
            raise SignatureError("Invalid public key.")
        return False

    if not isinstance(msg, (bytes, bytearray)):
        if strict:
            raise SignatureError("Invalid message.")
        return False

    if not isinstance(sig, (bytes, bytearray)) or len(sig) != SIG_SIZE:
        if strict:
            raise SignatureError("Invalid signature length.")
        return False

    # Наконец, сравнение хэшей
    expected = hashlib.sha256(pub + msg).digest()
    return expected == sig
