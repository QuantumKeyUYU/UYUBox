"""High-level cryptographic orchestration layer.

This module abstracts interactions with the bundled ``zilant-prime-core``
package and prepares the ground for advanced features that were outlined in
our product roadmap:

* adaptive Argon2id profiles that take device health into account;
* multi-layer encryption policies;
* secure metadata separation;
* optional integration with post-quantum primitives.

The concrete algorithms are still provided by ``zilant-prime-core`` but this
manager adds convenience helpers and fallbacks so that the UI can surface rich
feedback even when optional components are unavailable on the target device.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, Optional

try:  # pragma: no cover - optional dependency import
    from zilant_prime_core.container import (
        pack_file,
        unpack_file,
        read_metadata,
    )
except Exception as exc:  # pragma: no cover - runtime environment fallback
    pack_file = unpack_file = read_metadata = None  # type: ignore[assignment]
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


class SecurityTier(str, Enum):
    """Represents adaptive Argon2id profiles."""

    LIGHT = "light"
    BALANCED = "balanced"
    HARDENED = "hardened"
    ULTRA = "ultra"


@dataclass
class CryptoReport:
    """Aggregated execution metadata returned to the UI layer."""

    ok: bool
    message: str
    tier: SecurityTier = SecurityTier.BALANCED
    duration_ms: Optional[int] = None
    metadata: Optional[Dict[str, str]] = None


class CryptoManager:
    """Facade responsible for cryptographic operations and profiling."""

    def __init__(self) -> None:
        self._last_profile: Optional[SecurityTier] = None

    @property
    def last_profile(self) -> Optional[SecurityTier]:
        return self._last_profile

    def _ensure_available(self) -> Optional[CryptoReport]:
        if _IMPORT_ERROR:
            return CryptoReport(
                ok=False,
                message=f"Ядро недоступно: {_IMPORT_ERROR}",
            )
        return None

    # Public API -----------------------------------------------------------------
    def pack(self, source: str, password: str, output_name: str, tier: SecurityTier) -> CryptoReport:
        fallback = self._ensure_available()
        if fallback:
            return fallback

        try:
            self._last_profile = tier
            pack_file(source, password, output_name)
        except Exception as exc:  # pragma: no cover - pass-through from core
            return CryptoReport(ok=False, message=f"Ошибка упаковки: {exc}", tier=tier)
        return CryptoReport(
            ok=True,
            message="Файл успешно упакован",
            tier=tier,
        )

    def unpack(self, source: str, password: str, output_name: str) -> CryptoReport:
        fallback = self._ensure_available()
        if fallback:
            return fallback
        try:
            unpack_file(source, password, output_name)
        except Exception as exc:  # pragma: no cover
            return CryptoReport(ok=False, message=f"Ошибка распаковки: {exc}")
        return CryptoReport(ok=True, message="Файл успешно распакован")

    def metadata(self, source: str) -> CryptoReport:
        fallback = self._ensure_available()
        if fallback:
            return fallback
        try:
            meta = read_metadata(source)
        except Exception as exc:  # pragma: no cover
            return CryptoReport(ok=False, message=f"Ошибка чтения: {exc}")
        decorated = {
            "filename": meta.get("filename", "unknown"),
            "created_at": meta.get("created_at", datetime.utcnow().isoformat()),
            "profile": meta.get("profile", self._last_profile or SecurityTier.BALANCED.value),
        }
        return CryptoReport(ok=True, message="Метаданные получены", metadata=decorated)

    def analyze_device_profile(self, battery_level: int, temperature_c: float) -> SecurityTier:
        """Simple heuristic used by the UI to suggest Argon2id cost."""

        if battery_level < 20 or temperature_c > 42:
            tier = SecurityTier.LIGHT
        elif battery_level < 50:
            tier = SecurityTier.BALANCED
        elif temperature_c < 35:
            tier = SecurityTier.ULTRA
        else:
            tier = SecurityTier.HARDENED
        self._last_profile = tier
        return tier


crypto_manager = CryptoManager()
