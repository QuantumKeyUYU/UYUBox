from __future__ import annotations


def integers(min_value=0, max_value=100):
    def strat():
        return min_value

    return strat


def text():
    return "example"


def binary(min_size=0, max_size=10):
    def strat():
        return b"\x00" * max(min_size, 1)

    return strat
