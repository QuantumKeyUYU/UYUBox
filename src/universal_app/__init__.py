"""Simple universal encryption application."""

from __future__ import annotations

import json
from pathlib import Path

__all__ = ["encrypt_file", "decrypt_file"]


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encrypt_file(input_path: str, output_path: str, key: bytes, *, max_tries: int = 3, one_time: bool = False) -> None:
    """Encrypt a file using XOR and store metadata."""
    data = Path(input_path).read_bytes()
    ct = _xor(data, key)
    meta = {"tries": 0, "max_tries": max_tries, "one_time": one_time}
    payload = json.dumps(meta).encode() + b"\n" + ct
    Path(output_path).write_bytes(payload)


def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """Decrypt a file previously encrypted with :func:`encrypt_file`.\n
    Raises ``RuntimeError`` if reuse exceeds limits."""
    raw = Path(input_path).read_bytes()
    meta_json, ct = raw.split(b"\n", 1)
    meta = json.loads(meta_json.decode())
    tries = int(meta.get("tries", 0)) + 1
    max_tries = int(meta.get("max_tries", 0))
    one_time = bool(meta.get("one_time", False))
    if one_time and tries > 1:
        raise RuntimeError("One-time container reuse detected")
    if not one_time and tries > max_tries:
        raise RuntimeError("Max tries exceeded")

    data = _xor(ct, key)
    Path(output_path).write_bytes(data)
    meta["tries"] = tries
    Path(input_path).write_bytes(json.dumps(meta).encode() + b"\n" + ct)
