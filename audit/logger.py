"""Offline audit logging with Ed25519 signatures and hash chaining."""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict

try:  # pragma: no cover - import guarded for optional dependency
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ModuleNotFoundError:  # pragma: no cover - optional dependency missing at runtime
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment]
    _CRYPTOGRAPHY_AVAILABLE = False
else:
    _CRYPTOGRAPHY_AVAILABLE = True


def _resolve_audit_dir() -> Path:
    """Return the directory where audit artefacts should be stored.

    Tests and power users can point the logger to a custom location via the
    ``ZILANT_AUDIT_DIR`` environment variable. When the variable is not set we
    fall back to the user's home directory, preserving the previous behaviour.
    """

    override = os.environ.get("ZILANT_AUDIT_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".zilant_audit"


AUDIT_DIR = _resolve_audit_dir()
AUDIT_DIR.mkdir(parents=True, exist_ok=True)
KEY_PATH = AUDIT_DIR / "signing_key.pem"
CHAIN_STATE_PATH = AUDIT_DIR / "chain.state"


def _load_private_key() -> Ed25519PrivateKey:
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("cryptography backend is not available")
    if KEY_PATH.exists():
        data = KEY_PATH.read_bytes()
        return serialization.load_pem_private_key(data, password=None)
    private_key = Ed25519PrivateKey.generate()
    KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return private_key


def _load_prev_hash() -> str:
    try:
        return CHAIN_STATE_PATH.read_text().strip()
    except FileNotFoundError:
        return "GENESIS"


def _store_chain_hash(hash_hex: str) -> None:
    CHAIN_STATE_PATH.write_text(hash_hex)


def record_event(event: str, *, details: Dict[str, Any] | None = None) -> Path:
    timestamp = int(time.time())
    prev_hash = _load_prev_hash()
    payload = {
        "event": event,
        "details": details or {},
        "timestamp": timestamp,
        "prev_hash": prev_hash,
    }
    message = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if _CRYPTOGRAPHY_AVAILABLE:
        private_key = _load_private_key()
        signature = private_key.sign(message)
        chain_hash = hashlib.sha3_512(message + signature).hexdigest()
        entry = {
            "payload": payload,
            "signature": signature.hex(),
            "chain_hash": chain_hash,
        }
    else:
        signature = None
        chain_hash = hashlib.sha3_512(message).hexdigest()
        entry = {
            "payload": payload,
            "signature": None,
            "chain_hash": chain_hash,
            "crypto": "disabled",
        }
    file_path = AUDIT_DIR / f"audit_{timestamp}_{uuid.uuid4().hex}.json"
    file_path.write_text(json.dumps(entry, ensure_ascii=False, indent=2))
    _store_chain_hash(chain_hash)
    return file_path


def verify_log(path: os.PathLike[str] | str) -> bool:
    data = json.loads(Path(path).read_text())
    payload = json.dumps(data["payload"], ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature_hex = data.get("signature")
    signature = bytes.fromhex(signature_hex) if signature_hex else b""
    if not _CRYPTOGRAPHY_AVAILABLE:
        expected_chain_hash = hashlib.sha3_512(payload).hexdigest()
        return expected_chain_hash == data.get("chain_hash")
    private_key = _load_private_key()
    public_key = private_key.public_key()
    try:
        public_key.verify(signature, payload)
        expected_chain_hash = hashlib.sha3_512(payload + signature).hexdigest()
        return expected_chain_hash == data.get("chain_hash")
    except Exception:
        return False
