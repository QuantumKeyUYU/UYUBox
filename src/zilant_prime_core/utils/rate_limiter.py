# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

from __future__ import annotations

import math
import time

__all__ = ["RateLimiter"]


class RateLimiter:
    def __init__(self, rate: float, capacity: float) -> None:
        self._rate = float(rate)
        self._cap = float(capacity)
        self._tokens = float(capacity)
        self._t_last = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        self._tokens = min(self._cap, self._tokens + (now - self._t_last) * self._rate)
        self._t_last = now
        available = math.floor(self._tokens)
        take = min(1.0, float(available))
        self._tokens -= take
        return bool(available)
