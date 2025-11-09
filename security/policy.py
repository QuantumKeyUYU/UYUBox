"""Centralised security policy configuration.

The policy aggregates the most sensitive tunables so that both the UI and the
backend components share a single source of truth. Values can be overridden by
environment variables which keeps the application flexible for enterprise
deployments without requiring code changes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _load_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _load_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class SecurityPolicy:
    """Holds runtime tunables for critical security limits."""

    session_ttl: float = 180.0
    max_file_size_mb: int = 512
    min_free_space_mb: int = 256
    headroom_mb: int = 64


def load_policy() -> SecurityPolicy:
    """Load the security policy considering environment overrides."""

    return SecurityPolicy(
        session_ttl=_load_float("ZILANT_SESSION_TTL", 180.0),
        max_file_size_mb=_load_int("ZILANT_MAX_FILE_MB", 512),
        min_free_space_mb=_load_int("ZILANT_MIN_FREE_MB", 256),
        headroom_mb=_load_int("ZILANT_HEADROOM_MB", 64),
    )


policy = load_policy()


__all__ = ["SecurityPolicy", "policy", "load_policy"]
