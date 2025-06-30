# src/shamir.py
"""
Minimal Shamir’s Secret Sharing implementation for 16‐byte shares.
"""

_PRIME = 2**127 - 1  # must be > any secret < 16 bytes


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


def recover_secret(points: list[tuple[int, int]]) -> int:
    """
    Recover secret integer from (x, y) points on polynomial.
    """
    return _lagrange_interpolate(0, points)
