# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT
"""Упаковка / распаковка упрощённого .zil‑контейнера."""

from __future__ import annotations

import json
import struct
from typing import Any, Callable, Dict

__all__ = [
    "SelfDestructError",
    "pack_zill",
    "unpack_zil",
]


class SelfDestructError(Exception):
    """Подбрасывается при превышении числа попыток."""


def pack_zill(
    payload: bytes,
    formula: Callable[..., Any],  # не используется, но тип нужен
    lam: int,
    steps: int,
    key: bytes,
    salt: bytes,
    nonce: bytes,
    metadata: Dict[str, Any],
    max_tries: int,
    one_time: bool,
) -> bytes:
    """
    Упаковывает данные вместе с JSON‑метаданными,
    добавляя max_tries и флаг one_time.
    """
    meta: Dict[str, Any] = metadata.copy()
    meta["max_tries"] = max_tries
    meta["one_time"] = one_time
    meta_bytes = json.dumps(meta).encode("utf-8")

    return struct.pack(">I", len(meta_bytes)) + meta_bytes + payload


def unpack_zil(
    data: bytes,
    formula: Callable[..., Any],
    key: bytes,
    out_dir: str,
) -> bytes:
    """
    Распаковывает контейнер, проверяет число попыток и,
    при необходимости, выбрасывает SelfDestructError.
    """
    offset = 0
    total = len(data)

    meta_len = struct.unpack_from(">I", data, offset)[0]
    offset += 4

    meta_bytes = data[offset : offset + meta_len]
    offset += meta_len
    metadata: Dict[str, Any] = json.loads(meta_bytes.decode("utf-8"))

    payload = data[offset:total]

    tries = int(metadata.get("tries", 0))
    max_tries = int(metadata.get("max_tries", 0))
    one_time = bool(metadata.get("one_time", False))

    if one_time and tries > 0:
        raise SelfDestructError("One‑time container can’t be reused.")
    if not one_time and tries >= (max_tries - 1):
        raise SelfDestructError("Max tries exceeded.")

    return payload
