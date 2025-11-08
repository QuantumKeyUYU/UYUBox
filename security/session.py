"""Ephemeral session management with automatic invalidation."""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from audit.logger import record_event
from security.policy import policy


class SessionError(RuntimeError):
    """Raised when the secure session is not available."""


@dataclass
class _SessionState:
    token: str
    expires_at: float


class SessionManager:
    """Maintain a short-lived session token for privileged actions."""

    def __init__(self, default_ttl: float = 180.0) -> None:
        self.default_ttl = default_ttl
        self._lock = threading.Lock()
        self._state: _SessionState | None = None
        self._invalid_reason: str | None = None

    def activate(self, *, ttl: float | None = None) -> str:
        """Start a new session that automatically expires after *ttl* seconds."""

        lifetime = ttl or self.default_ttl
        expires_at = time.monotonic() + lifetime
        token = secrets.token_hex(16)
        with self._lock:
            self._state = _SessionState(token=token, expires_at=expires_at)
            self._invalid_reason = None
        record_event(
            "session.activated",
            details={"ttl": lifetime, "expires_at": expires_at},
        )
        return token

    def invalidate(self, reason: str) -> None:
        """Permanently drop the current session and store *reason* for auditing."""

        with self._lock:
            self._state = None
            self._invalid_reason = reason
        record_event("session.invalidated", details={"reason": reason})

    def require_active(self) -> str:
        """Return the active session token or raise :class:`SessionError`."""

        with self._lock:
            if self._invalid_reason:
                raise SessionError(self._invalid_reason)
            state = self._state
            if state is None:
                raise SessionError("Сессия не активна. Разблокируйте приложение.")
            now = time.monotonic()
            if now >= state.expires_at:
                self._state = None
                self._invalid_reason = "Сессия истекла. Повторно пройдите аутентификацию."
                record_event(
                    "session.expired",
                    details={"expired_at": state.expires_at},
                )
                raise SessionError(self._invalid_reason)
            return state.token

    def remaining_ttl(self) -> float:
        """Return the remaining lifetime in seconds or ``0`` if inactive."""

        with self._lock:
            state = self._state
            if not state:
                return 0.0
            return max(0.0, state.expires_at - time.monotonic())

    def clear(self) -> None:
        """Drop the current session without marking it invalid."""

        with self._lock:
            self._state = None
            self._invalid_reason = None
        record_event("session.cleared", details={})


session_manager = SessionManager(default_ttl=policy.session_ttl)


__all__ = ["SessionError", "SessionManager", "session_manager"]
