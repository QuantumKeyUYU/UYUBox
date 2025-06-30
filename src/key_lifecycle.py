# src/key_lifecycle.py

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from typing import List, cast

import shamir  # our local shamir.py stub


class KeyLifecycle:
    """Key derivation and rotation utilities."""

    @staticmethod
    def derive_session_key(master_key: bytes, context: str) -> bytes:
        h = hashlib.blake2s(context.encode(), key=master_key)
        return cast(bytes, h.digest())

    @staticmethod
    def rotate_master_key(old_key: bytes, days: int) -> bytes:
        data = days.to_bytes(4, "big", signed=False)
        return cast(bytes, hashlib.blake2s(data, key=old_key).digest())


def shard_secret(secret: bytes, n: int, t: int) -> List[bytes]:
    if not 1 <= t <= n:
        raise ValueError("Invalid threshold")
    value = int.from_bytes(secret, "big")
    if value >= shamir._PRIME:
        raise ValueError("Secret too large")
    # random polynomial of degree t−1
    poly = [value] + [secrets.randbelow(shamir._PRIME) for _ in range(t - 1)]

    def eval_at(x: int) -> int:
        acc = 0
        for coeff in reversed(poly):
            acc = (acc * x + coeff) % shamir._PRIME
        return acc

    shares: List[bytes] = []
    for i in range(1, n + 1):
        x_b = i.to_bytes(1, "big")
        y_b = eval_at(i).to_bytes(16, "big")
        shares.append(x_b + y_b)
    return shares


def recover_secret(shards: List[bytes]) -> bytes:
    if not shards:
        return b""
    points: list[tuple[int, int]] = []
    for sh in shards:
        if len(sh) < 17:
            raise ValueError("Invalid shard")
        x, y = sh[0], int.from_bytes(sh[1:17], "big")
        points.append((x, y))
    secret_int = shamir.recover_secret(points)
    length = (secret_int.bit_length() + 7) // 8
    return cast(bytes, secret_int.to_bytes(length, "big"))


class AuditLog:
    """Append-only audit log secured with hash chaining."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path("audit.log")

    def append_event(self, event: str) -> None:
        prev = self._last_digest()
        new = hashlib.sha256(prev + event.encode()).digest()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(f"{new.hex()} {event}\n")

    def _last_digest(self) -> bytes:
        if not self.path.exists():
            return b""
        lines = self.path.read_bytes().splitlines()
        if not lines:
            return b""
        last = lines[-1].split(b" ", 1)[0]
        try:
            return bytes.fromhex(last.decode())
        except Exception:
            return b""

    def verify_log(self) -> bool:
        digest = b""
        if not self.path.exists():
            return True
        for line in self.path.read_text().splitlines():
            hex_d, evt = line.split(" ", 1)
            digest = hashlib.sha256(digest + evt.encode()).digest()
            if digest.hex() != hex_d:
                return False
        return True
