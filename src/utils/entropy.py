# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

import os
import time

__all__ = ["get_random_bytes"]


def get_random_bytes(n: int) -> bytes:
    """Return ``n`` cryptographically strong random bytes."""
    if n <= 0:
        raise ValueError("n must be positive")
    # try os.getrandom if available
    if hasattr(os, "getrandom"):
        return os.getrandom(n)  # type: ignore[no-any-return]
    # fallback: mix time jitter with urandom
    time.sleep(0.001)
    return os.urandom(n)
