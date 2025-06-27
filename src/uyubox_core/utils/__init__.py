# SPDX-FileCopyrightText: 2024‑2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT
"""
Пакет util‑ов ядра ZILANT Prime™.
"""

from __future__ import annotations

from .anti_snapshot import detect_snapshot

# ──────────────────────── Public constants ──────────────────────────
from .constants import (
    DEFAULT_KEY_LENGTH,
    DEFAULT_NONCE_LENGTH,
    DEFAULT_SALT_LENGTH,
    HEADER_FMT,
    HEADER_SIZE,
    MAGIC,
    VERSION,
)
from .counter import increment_counter, read_counter, write_counter

# ───────────────────────── Pseudo-HSM placeholders ──────────────────────────
from .device_fp import get_device_fingerprint
from .device_fp_fallback import device_fp_fallback

# ───────────────────────── Encode / decode ──────────────────────────
from .formats import from_b64, from_hex, to_b64, to_hex
from .hash_challenge import generate_daily_challenge
from .honeyfile import HoneyfileError, check_tmp_for_honeyfiles

# ───────────────────────────── Logging ──────────────────────────────
from .logging import get_file_logger, get_logger
from .root_guard import assert_safe_or_die, is_device_rooted
from .screen_guard import ScreenGuard, ScreenGuardError, guard
from .secure_logging import SecureLogger, get_secure_logger
from .shard_secret import recover_secret, split_secret

# ───────────────────────── Vault integration ────────────────────────
from .vault_client import VaultClient

__all__: list[str] = [
    # constants.py
    "DEFAULT_KEY_LENGTH",
    "DEFAULT_NONCE_LENGTH",
    "DEFAULT_SALT_LENGTH",
    "HEADER_FMT",
    "HEADER_SIZE",
    "MAGIC",
    "VERSION",
    # formats.py
    "from_b64",
    "from_hex",
    "to_b64",
    "to_hex",
    # logging.py
    "get_logger",
    "get_file_logger",
    # secure_logging.py
    "SecureLogger",
    "get_secure_logger",
    # vault_client.py
    "VaultClient",
    # device fingerprint
    "get_device_fingerprint",
    "device_fp_fallback",
    # shard secret
    "split_secret",
    "recover_secret",
    # counter
    "read_counter",
    "write_counter",
    "increment_counter",
    # anti snapshot
    "detect_snapshot",
    "assert_safe_or_die",
    "is_device_rooted",
    "ScreenGuard",
    "ScreenGuardError",
    "guard",
    "HoneyfileError",
    "check_tmp_for_honeyfiles",
    "generate_daily_challenge",
]
