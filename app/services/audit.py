"""Transparent audit log prototype built on top of an in-memory ledger."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import List, Optional


@dataclass
class AuditEvent:
    timestamp: datetime
    actor: str
    action: str
    payload_hash: str
    previous_hash: Optional[str]

    @property
    def digest(self) -> str:
        contents = f"{self.timestamp.isoformat()}|{self.actor}|{self.action}|{self.payload_hash}|{self.previous_hash}"
        return sha256(contents.encode("utf-8")).hexdigest()


class AuditLedger:
    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def record(self, actor: str, action: str, payload: str) -> AuditEvent:
        payload_hash = sha256(payload.encode("utf-8")).hexdigest()
        previous_hash = self._events[-1].digest if self._events else None
        event = AuditEvent(
            timestamp=datetime.utcnow(),
            actor=actor,
            action=action,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
        )
        self._events.append(event)
        return event

    def tail(self, limit: int = 20) -> List[AuditEvent]:
        return list(reversed(self._events[-limit:]))


audit_ledger = AuditLedger()
