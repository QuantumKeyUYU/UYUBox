from __future__ import annotations


def binary(min_size: int = 0, max_size: int = 64):
    def gen():
        size = max(min_size, 1)
        return b"0" * size

    return gen


def integers(min_value: int = 0, max_value: int = 100):
    def gen() -> int:
        return max(min_value, 0)

    return gen
