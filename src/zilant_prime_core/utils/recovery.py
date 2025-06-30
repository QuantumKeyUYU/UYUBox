# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Self-destruct utilities for emergency recovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from aead import encrypt
from utils.file_utils import atomic_write
from utils.logging import get_logger
from utils.secure_memory import wipe_bytes

LOG_FILE = Path.home() / ".zilant_log.json"
LOG_ENC_FILE = Path.home() / ".zilant_log.enc"
DECOY_FILE = Path(__file__).resolve().parents[2] / "dist" / "decoy_template.bin"

DESTRUCTION_KEY_BUFFER: bytearray = bytearray(b"0123456789ABCDEF0123456789ABCDEF")

logger = get_logger("recovery")


def self_destruct(reason: str, key_buffer: bytearray) -> Optional[bytes]:
    """Encrypt log, wipe key and produce decoy data.

    Parameters
    ----------
    reason: str
        Reason for triggering destruction.
    key_buffer: bytearray
        AES key stored as mutable buffer.

    Returns
    -------
    Optional[bytes]
        Content of the generated decoy file.

    Raises
    ------
    RuntimeError
        If ``key_buffer`` is not bytes-like.
    FileNotFoundError
        If ``DECOY_FILE`` is missing.
    Exception
        Propagates encryption or write errors.
    """

    if not isinstance(key_buffer, (bytes, bytearray)):
        raise RuntimeError("No destruction key available or wrong type")

    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 0:
            log_data = LOG_FILE.read_bytes()
            nonce = os.urandom(12)
            aes_key = bytes(key_buffer)
            _, enc = encrypt(aes_key, log_data, aad=b"")
            meta = {"nonce_hex": nonce.hex(), "reason": reason}
            data = json.dumps(meta).encode("utf-8") + b"\n\n" + enc
            tmp = LOG_ENC_FILE.with_suffix(LOG_ENC_FILE.suffix + ".tmp")
            atomic_write(tmp, data)
            tmp.replace(LOG_ENC_FILE)
            logger.critical("Log encrypted to %s", LOG_ENC_FILE)
        else:
            logger.warning("No log file to encrypt")

        if isinstance(key_buffer, bytearray):
            wipe_bytes(key_buffer)

        if not DECOY_FILE.exists():
            raise FileNotFoundError("decoy.bin not found")
        decoy_data = DECOY_FILE.read_bytes()
        atomic_write(Path.cwd() / "decoy.bin", decoy_data)
        logger.info("Decoy file generated in current directory")
        return decoy_data
    except Exception as exc:  # pragma: no cover - unexpected errors
        logger.error("Self-destruct failed: %s", exc)
        raise
