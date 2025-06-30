# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
"""Argon2‑cffi with PBKDF2 fallback (hash_password / verify_password)."""

from __future__ import annotations

import base64
import hashlib
from typing import Final, cast

try:
    from argon2 import PasswordHasher  # type: ignore
    from argon2.exceptions import VerifyMismatchError  # pragma: no cover
except ModuleNotFoundError:  # pragma: no cover
    # ── PBKDF2 fallback ──
    _SALT: Final[bytes] = b"zilant-prime-core"

    def hash_password(password: str) -> str:  # pragma: no cover
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), _SALT, 50_000)
        return base64.b64encode(dk).decode()

    def verify_password(hash_: str, password: str) -> bool:  # pragma: no cover
        return hash_ == hash_password(password)

else:
    # ── Primary Argon2id path ──
    _PH: Final[PasswordHasher] = PasswordHasher(  # pragma: no cover
        time_cost=2,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=32,
    )

    def hash_password(password: str) -> str:  # pragma: no cover
        return cast(str, _PH.hash(password))  # pragma: no cover

    def verify_password(hash_: str, password: str) -> bool:  # pragma: no cover
        try:
            return cast(bool, _PH.verify(hash_, password))  # pragma: no cover
        except VerifyMismatchError:  # pragma: no cover
            return False  # pragma: no cover
