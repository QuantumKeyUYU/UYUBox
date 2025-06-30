# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
from zilant_prime_core.utils.rate_limiter import RateLimiter


def test_rate_limiter_allows_at_rate():
    rl = RateLimiter(rate=2, capacity=2)
    allowed = sum(1 for _ in range(10) if rl.allow())
    assert allowed == 2
