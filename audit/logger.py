"""Offline audit logging with Ed25519 signatures."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

AUDIT_DIR = Path.home() / ".zilant_audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)
KEY_PATH = AUDIT_DIR / "signing_key.pem"


def _load_private_key() -> Ed25519PrivateKey:
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


def record_event(event: str, *, details: Dict[str, Any] | None = None) -> Path:
    private_key = _load_private_key()
    timestamp = int(time.time())
    payload = {
        "event": event,
        "details": details or {},
        "timestamp": timestamp,
    }
    message = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature = private_key.sign(message)
    entry = {
        "payload": payload,
        "signature": signature.hex(),
    }
    file_path = AUDIT_DIR / f"audit_{timestamp}.json"
    file_path.write_text(json.dumps(entry, ensure_ascii=False, indent=2))
    return file_path


def verify_log(path: os.PathLike[str] | str) -> bool:
    data = json.loads(Path(path).read_text())
    payload = json.dumps(data["payload"], ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature = bytes.fromhex(data["signature"])
    private_key = _load_private_key()
    public_key = private_key.public_key()
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False
