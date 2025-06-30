# src/shamir.py
"""Minimal Shamir’s Secret Sharing implementation for small secrets.

This module provides two helper functions:

``split_secret``
    Split an integer secret into ``n`` shares with a reconstruction threshold
    of ``k`` using a random polynomial.

``recover_secret``
    Reconstruct the original secret from share points produced by
    :func:`split_secret`.
"""

_PRIME = 2**127 - 1  # must be > any secret < 16 bytes

import secrets


def _lagrange_interpolate(x: int, points: list[tuple[int, int]]) -> int:
    """Perform Lagrange interpolation at x=0 over the given points."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (x - xj)) % _PRIME
            den = (den * (xi - xj)) % _PRIME
        total = (total + yi * num * pow(den, -1, _PRIME)) % _PRIME
    return total


def split_secret(secret: int, *, n: int, k: int) -> list[tuple[int, int]]:
    """Split ``secret`` into ``n`` shares with threshold ``k``."""
    if not (0 < k <= n <= 255):
        raise ValueError("Invalid n or k")
    if secret < 0 or secret >= _PRIME:
        raise ValueError("Secret out of range")

    coeffs = [secret] + [secrets.randbelow(_PRIME) for _ in range(k - 1)]

    shares: list[tuple[int, int]] = []
    for x in range(1, n + 1):
        y = 0
        power = 1
        for c in coeffs:
            y = (y + c * power) % _PRIME
            power = (power * x) % _PRIME
        shares.append((x, y))
    return shares


def recover_secret(points: list[tuple[int, int]]) -> int:
    """
    Recover secret integer from (x, y) points on polynomial.
    """
    return _lagrange_interpolate(0, points)
