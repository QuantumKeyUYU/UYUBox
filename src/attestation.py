from __future__ import annotations

"""TPM attestation helpers (simulated)."""

import hashlib
import time
from typing import Any, Dict


def simulate_tpm_attestation(data: bytes) -> Dict[str, Any]:
    """Return dummy attestation info for ``data``."""
    return {
        "timestamp": int(time.time()),
        "hash": hashlib.sha256(data).hexdigest(),
        "evidence": "dummy",
    }
