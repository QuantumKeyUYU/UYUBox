# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, cast

from aead import PQAEAD, decrypt, encrypt
from crypto_core import hash_sha3
from utils.file_utils import atomic_write
from utils.logging import get_logger

ZIL_MAGIC = b"ZILANT"
ZIL_VERSION = 1
HEADER_SEPARATOR = b"\n\n"

logger = get_logger("container")

# in-memory counter of unpack attempts per container path
_ATTEMPTS: DefaultDict[str, int] = defaultdict(int)


def _record_attempt(path: Path) -> None:
    _ATTEMPTS[str(path)] += 1


def get_open_attempts(path: Path) -> int:
    """Return number of times ``unpack_file`` was called for this container."""
    return _ATTEMPTS.get(str(path), 0)


def pack_file(
    input_path: Path,
    output_path: Path,
    key: bytes,
    pq_public_key: bytes | None = None,
    *,
    extra_meta: dict[str, Any] | None = None,
) -> None:
    if not isinstance(input_path, Path):
        raise TypeError("input_path must be a pathlib.Path")
    if not isinstance(output_path, Path):
        raise TypeError("output_path must be a pathlib.Path")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long")

    plaintext = input_path.read_bytes()
    checksum = cast(bytes, hash_sha3(plaintext))

    if pq_public_key is not None:
        if not isinstance(pq_public_key, (bytes, bytearray)):
            raise TypeError("pq_public_key must be bytes")
        payload = PQAEAD.encrypt(pq_public_key, plaintext, aad=b"")
        meta_pq: dict[str, Any] = {
            "magic": ZIL_MAGIC.decode("ascii"),
            "version": ZIL_VERSION,
            "mode": "pq",
            "kem_ct_len": len(payload) - len(plaintext) - PQAEAD._NONCE_LEN,
            "orig_size": len(plaintext),
            "checksum_hex": checksum.hex(),
        }
        if extra_meta:
            meta_pq.update(extra_meta)
        meta_pq.setdefault("heal_level", 0)
        meta_pq.setdefault("heal_history", [])
        header_bytes = json.dumps(meta_pq, ensure_ascii=False).encode("utf-8")
        container_data = header_bytes + HEADER_SEPARATOR + payload
    else:
        nonce, ciphertext = encrypt(key, plaintext, aad=b"")
        meta_classic: dict[str, Any] = {
            "magic": ZIL_MAGIC.decode("ascii"),
            "version": ZIL_VERSION,
            "mode": "classic",
            "nonce_hex": nonce.hex(),
            "orig_size": len(plaintext),
            "checksum_hex": checksum.hex(),
        }
        if extra_meta:
            meta_classic.update(extra_meta)
        meta_classic.setdefault("heal_level", 0)
        meta_classic.setdefault("heal_history", [])
        header_bytes = json.dumps(meta_classic, ensure_ascii=False).encode("utf-8")
        container_data = header_bytes + HEADER_SEPARATOR + ciphertext

    tmp = output_path.with_suffix(output_path.suffix + ".tmp")
    atomic_write(tmp, container_data)
    tmp.replace(output_path)
    logger.info(
        "Packed '%s' -> '%s', size=%d bytes",
        input_path.name,
        output_path.name,
        len(container_data),
    )


def unpack_file(
    input_path: Path,
    output_path: Path,
    key: bytes,
    pq_private_key: bytes | None = None,
) -> None:
    if not isinstance(input_path, Path):
        raise TypeError("input_path must be a pathlib.Path")
    if not isinstance(output_path, Path):
        raise TypeError("output_path must be a pathlib.Path")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long")

    _record_attempt(input_path)

    try:
        data = input_path.read_bytes()
        sep_idx = data.find(HEADER_SEPARATOR)
        if sep_idx == -1:
            raise ValueError("Invalid ZIL container format")

        header_bytes = data[:sep_idx]
        payload = data[sep_idx + len(HEADER_SEPARATOR) :]
        meta: dict[str, Any] = json.loads(header_bytes.decode("utf-8"))

        if meta.get("magic") != ZIL_MAGIC.decode("ascii"):
            raise ValueError("Invalid ZIL magic value")
        if meta.get("version") != ZIL_VERSION:
            raise ValueError("Unsupported ZIL version")

        mode = meta.get("mode", "classic")
        orig_size = meta["orig_size"]
        checksum_hex = meta["checksum_hex"]

        if mode == "pq":
            if not isinstance(pq_private_key, (bytes, bytearray)):
                raise TypeError("pq_private_key must be bytes")
            kem_len = meta["kem_ct_len"]
            kem_ct = payload[:kem_len]
            nonce = payload[kem_len : kem_len + PQAEAD._NONCE_LEN]
            ct = payload[kem_len + PQAEAD._NONCE_LEN :]
            from zilant_prime_core.utils.pq_crypto import Kyber768KEM, derive_key_pq

            kem = Kyber768KEM()
            shared = kem.decapsulate(pq_private_key, kem_ct)
            key_dec = derive_key_pq(shared)
            plaintext = decrypt(key_dec, nonce, ct, aad=b"")
        else:
            nonce = bytes.fromhex(meta["nonce_hex"])
            plaintext = decrypt(key, nonce, payload, aad=b"")

        actual_checksum = cast(bytes, hash_sha3(plaintext)).hex()
        if actual_checksum != checksum_hex:
            raise ValueError("Integrity check failed")
        if len(plaintext) != orig_size:
            raise ValueError("Original size mismatch")

        atomic_write(output_path, plaintext)
        logger.info("Unpacked '%s' -> '%s'", input_path.name, output_path.name)
    except ValueError:
        try:
            from audit_ledger import record_action
            from zilant_prime_core.notify import Notifier

            record_action("tamper_detected", {"file": str(input_path)})
            Notifier().notify(f"Tamper detected in {input_path.name}")
        except Exception:
            pass
        raise


def pack(meta: dict[str, Any], payload: bytes, key: bytes) -> bytes:
    if not isinstance(meta, dict):
        raise TypeError("meta must be a dict")
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long")

    header_bytes: bytes = json.dumps(meta, ensure_ascii=False).encode("utf-8") + HEADER_SEPARATOR
    nonce, ciphertext = encrypt(key, payload, aad=b"")
    return header_bytes + nonce + ciphertext


def unpack(blob: bytes, key: bytes) -> tuple[dict[str, Any], bytes]:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long")

    sep_idx = blob.find(HEADER_SEPARATOR)
    if sep_idx == -1:
        raise ValueError("Invalid blob format")

    header_bytes = blob[:sep_idx]
    payload = blob[sep_idx + len(HEADER_SEPARATOR) :]
    meta: dict[str, Any] = json.loads(header_bytes.decode("utf-8"))
    nonce = payload[:12]
    ciphertext = payload[12:]
    plaintext = decrypt(key, nonce, ciphertext, aad=b"")
    return meta, plaintext


def get_metadata(path: Path) -> dict[str, Any]:
    """Extract container metadata without decrypting payload."""
    data = path.read_bytes()
    sep_idx = data.find(HEADER_SEPARATOR)
    if sep_idx == -1:
        raise ValueError("Invalid ZIL container format")
    header_bytes = data[:sep_idx]
    meta = cast(dict[str, Any], json.loads(header_bytes.decode("utf-8")))
    meta.setdefault("heal_level", 0)
    meta.setdefault("heal_history", [])
    meta.setdefault("recovery_key_hex", None)
    return meta


def verify_integrity(path: Path) -> bool:
    """Quickly check container header structure without decrypting."""
    data = path.read_bytes()
    sep_idx = data.find(HEADER_SEPARATOR)
    if sep_idx == -1:
        return False
    try:
        meta = cast(dict[str, Any], json.loads(data[:sep_idx].decode("utf-8")))
    except Exception:
        return False
    if meta.get("magic") != ZIL_MAGIC.decode("ascii"):
        return False
    if meta.get("version") != ZIL_VERSION:
        return False
    payload = data[sep_idx + len(HEADER_SEPARATOR) :]
    orig_size = cast(int, meta.get("orig_size", 0))
    return len(payload) >= orig_size


__all__ = [
    "pack_file",
    "unpack_file",
    "pack",
    "unpack",
    "get_metadata",
    "get_open_attempts",
    "verify_integrity",
    "ZIL_MAGIC",
    "ZIL_VERSION",
    "HEADER_SEPARATOR",
]
