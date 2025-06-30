# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Uniform-size encrypted container."""

from __future__ import annotations

import json
import os
from typing import Any, Tuple

from .crypto_core import decrypt_chacha20_poly1305, encrypt_chacha20_poly1305

__all__ = ["pack", "unpack"]

_PAD = 4096


def _pad(data: bytes) -> bytes:
    rem = (-len(data)) % _PAD
    return data + b"\x00" * rem


def pack(metadata: dict[str, Any], payload: bytes, key: bytes) -> bytes:
    meta_with_len = dict(metadata)
    meta_with_len["_payload_length"] = len(payload)
    meta_json = json.dumps(meta_with_len).encode()
    plain = len(meta_json).to_bytes(4, "big") + meta_json + payload
    blob = _pad(plain)
    nonce = os.urandom(12)
    ct = encrypt_chacha20_poly1305(key, nonce, blob)
    return nonce + ct


def unpack(blob: bytes, key: bytes) -> Tuple[dict[str, Any], bytes]:
    nonce = blob[:12]
    ct = blob[12:]
    plain = decrypt_chacha20_poly1305(key, nonce, ct)
    meta_len = int.from_bytes(plain[:4], "big")
    meta_json = plain[4 : 4 + meta_len]
    meta_with_len = json.loads(meta_json.decode())
    try:
        payload_length = meta_with_len.pop("_payload_length")
    except KeyError as exc:
        raise ValueError("missing payload length in metadata") from exc
    payload_start = 4 + meta_len
    payload = plain[payload_start : payload_start + payload_length]
    return meta_with_len, payload
