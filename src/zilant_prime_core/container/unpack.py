# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from zilant_prime_core.container.metadata import (
    MetadataError,
    deserialize_metadata,
    new_meta_for_file,
    serialize_metadata,
)
from zilant_prime_core.crypto.aead import (
    DEFAULT_NONCE_LENGTH,
    AEADInvalidTagError,
    decrypt_aead,
    encrypt_aead,
    generate_nonce,
)
from zilant_prime_core.crypto.kdf import DEFAULT_SALT_LENGTH, derive_key

__all__ = [
    "PackError",
    "UnpackError",
    "pack",
    "unpack",
]


class PackError(Exception):
    pass


class UnpackError(Exception):
    pass


def _pack_bytes(src: Path, password: str) -> bytes:
    meta_blob = serialize_metadata(new_meta_for_file(src))
    salt = os.urandom(DEFAULT_SALT_LENGTH)
    key = derive_key(password.encode(), salt)
    nonce = generate_nonce()
    ct = encrypt_aead(key, nonce, src.read_bytes(), aad=meta_blob)
    return len(meta_blob).to_bytes(4, "big") + meta_blob + salt + nonce + ct


def pack(path: str | Path, password: str) -> bytes:
    src = Path(path)
    if not src.is_file():
        raise PackError(f"{src} is not a regular file")
    return _pack_bytes(src, password)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise UnpackError(msg)


def unpack(container: bytes | Path, output_dir: str | Path, password: str) -> Path:
    raw = Path(container).read_bytes() if isinstance(container, Path) else container
    pos = 0

    _require(len(raw) >= 4, "Контейнер слишком мал для метаданных.")
    meta_len = int.from_bytes(raw[pos : pos + 4], "big")
    pos += 4

    _require(len(raw) >= pos + meta_len, "Неполные метаданные.")
    meta_blob = raw[pos : pos + meta_len]
    pos += meta_len

    try:
        meta: Mapping[str, Any] = deserialize_metadata(meta_blob)
    except MetadataError as exc:
        raise UnpackError(f"Не удалось разобрать метаданные: {exc}") from exc

    _require(len(raw) >= pos + DEFAULT_SALT_LENGTH, "Неправильный формат контейнера (salt).")
    salt = raw[pos : pos + DEFAULT_SALT_LENGTH]
    pos += DEFAULT_SALT_LENGTH

    _require(len(raw) >= pos + DEFAULT_NONCE_LENGTH, "Неправильный формат контейнера (nonce).")
    nonce = raw[pos : pos + DEFAULT_NONCE_LENGTH]
    pos += DEFAULT_NONCE_LENGTH

    ct_tag = raw[pos:]
    _require(len(ct_tag) >= 16, "Ciphertext слишком короткий для включения тега.")

    key = derive_key(password.encode(), salt)
    try:
        payload = decrypt_aead(key, nonce, ct_tag, aad=meta_blob)
    except AEADInvalidTagError:
        raise UnpackError("Неверная метка аутентификации.")

    try:
        filename = str(meta["filename"])
        size = int(meta["size"])
    except Exception as exc:
        raise UnpackError(f"Некорректные поля метаданных: {exc}") from exc

    _require(len(payload) == size, "Размер payload не совпадает с size из метаданных.")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_file = out_dir / filename
    if out_file.exists():
        raise FileExistsError(f"{out_file} already exists")
    out_file.write_bytes(payload)
    return out_file
