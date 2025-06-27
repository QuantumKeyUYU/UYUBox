# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Distributed counter with AES-GCM and HMAC anchor."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import requests
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
from typing import Optional, cast


class SecurityError(Exception):
    """Raised when counter integrity verification fails."""


class DistributedCounter:
    def __init__(self, path: Path, hmac_key: bytes, anchor_url: Optional[str] = None) -> None:
        self.path = path
        self.hmac_key = hmac_key
        self.anchor_url = anchor_url
        if len(hmac_key) < 32:
            raise ValueError("hmac_key too short")

    def _encrypt(self, data: bytes) -> bytes:
        aes = AESGCM(self.hmac_key[:32])
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, data, None)
        return cast(bytes, nonce + ct)

    def _decrypt(self, data: bytes) -> bytes:
        aes = AESGCM(self.hmac_key[:32])
        nonce, ct = data[:12], data[12:]
        return cast(bytes, aes.decrypt(nonce, ct, None))

    def verify_and_load(self) -> int:
        if not self.path.exists():
            return 0
        try:
            raw = self._decrypt(self.path.read_bytes())
            info = json.loads(raw.decode())
            count = int(info.get("count", 0))
            ts = float(info.get("timestamp", 0))
            hm = base64.b64decode(info.get("hmac", ""))
            mac = hmac.new(self.hmac_key, f"{count}|{ts}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(hm, mac):
                raise SecurityError("HMAC mismatch")
            return count
        except Exception as exc:
            raise SecurityError(str(exc)) from exc

    def _store(self, count: int) -> None:
        ts = time.time()
        mac = hmac.new(self.hmac_key, f"{count}|{ts}".encode(), hashlib.sha256).digest()
        payload = json.dumps({"count": count, "timestamp": ts, "hmac": base64.b64encode(mac).decode()}).encode()
        self.path.write_bytes(self._encrypt(payload))
        if self.anchor_url:
            try:
                requests.post(
                    self.anchor_url,
                    json={"count": count, "hmac": base64.b64encode(mac).decode()},
                )  # nosec B113 - best effort anchor reporting
            except KeyError:
                # optional anchor details missing; ignore failures
                pass

    def increment(self) -> int:
        current = self.verify_and_load()
        current += 1
        self._store(current)
        return current
