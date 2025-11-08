"""Integrity verification helpers for .zil containers."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

try:
    from zilant_prime_core.container import read_metadata
except Exception:  # pragma: no cover
    read_metadata = None  # type: ignore


class IntegrityError(RuntimeError):
    pass


def fingerprint(path: str | Path, *, chunk_size: int = 65536) -> str:
    sha = hashlib.sha3_512()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def verify_container(path: str | Path, *, expected_digest: Optional[str] = None) -> dict[str, str]:
    meta = {}
    if read_metadata:
        try:
            meta = read_metadata(str(path)) or {}
        except Exception as exc:
            raise IntegrityError(f"Ошибка чтения метаданных: {exc}") from exc
    digest = fingerprint(path)
    if expected_digest and digest != expected_digest:
        raise IntegrityError("Контрольная сумма не совпадает")
    meta["digest"] = digest
    return meta
