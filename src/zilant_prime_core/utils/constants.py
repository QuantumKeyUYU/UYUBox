# SPDX-FileCopyrightText: 2024–2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

from struct import calcsize

__all__ = [
    "DEFAULT_KEY_LENGTH",
    "DEFAULT_NONCE_LENGTH",
    "DEFAULT_SALT_LENGTH",
    "HEADER_FMT",
    "HEADER_SIZE",
    "MAGIC",
    "VERSION",
]

# Заголовок контейнера (не используется в JSON-режиме)
MAGIC = b"ZILP"  # 4-байтная магия
VERSION = 1  # 1-байтовая версия
HEADER_FMT = "!4sBIII"
HEADER_SIZE = calcsize(HEADER_FMT)

# AEAD / KDF константы
DEFAULT_KEY_LENGTH = 32  # байт
DEFAULT_NONCE_LENGTH = 12  # байт
DEFAULT_SALT_LENGTH = 16  # байт
