"""Secure sharing session management stubs."""
from __future__ import annotations

from dataclasses import dataclass
from secrets import token_urlsafe
from typing import Dict, List


@dataclass
class ShareSession:
    session_id: str
    pqc_suite: str
    participants: List[str]
    status: str = "pending"


class SecureShareGateway:
    """In-memory session registry that emulates zero-trust rooms."""

    def __init__(self) -> None:
        self._sessions: Dict[str, ShareSession] = {}

    def create_session(self, owner: str, pqc_suite: str) -> ShareSession:
        session_id = token_urlsafe(12)
        session = ShareSession(session_id=session_id, pqc_suite=pqc_suite, participants=[owner])
        self._sessions[session_id] = session
        return session

    def join(self, session_id: str, participant: str) -> ShareSession:
        session = self._sessions[session_id]
        if participant not in session.participants:
            session.participants.append(participant)
        if len(session.participants) >= 2:
            session.status = "ready"
        return session

    def all_sessions(self) -> List[ShareSession]:
        return list(self._sessions.values())


secure_share_gateway = SecureShareGateway()
