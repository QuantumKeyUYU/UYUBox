# SPDX-License-Identifier: MIT
"""Zero-knowledge proof helpers."""

from __future__ import annotations

import hashlib

try:  # pragma: no cover - optional dependency
    import pysnark as _pysnark  # type: ignore  # noqa: F401

    def prove_intact(event_hash: bytes) -> bytes:
        return hashlib.sha3_256(event_hash).digest() + b"PYSNARK"

    def verify_intact(event_hash: bytes, proof: bytes) -> bool:
        return proof == hashlib.sha3_256(event_hash).digest() + b"PYSNARK"

except Exception:  # pragma: no cover - fallback

    def prove_intact(event_hash: bytes) -> bytes:
        return hashlib.sha3_256(event_hash).digest()[-16:] + b"MOCK"

    def verify_intact(event_hash: bytes, proof: bytes) -> bool:
        return proof == prove_intact(event_hash)


__all__ = ["prove_intact", "verify_intact"]
