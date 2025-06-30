# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_g_new.py

import math
import pytest

from zilant_prime_core.crypto.g_new import G_new, GNewError


def test_g_new_basic():
    # возвращает float
    val = G_new(0.5)
    assert isinstance(val, float)


def test_g_new_known_value():
    # при x=0 оба синуса 0 → результат 0
    assert abs(G_new(0.0) - 0.0) < 1e-9


def test_g_new_periodicity():
    # G_new(x) == G_new(x + 2π)
    x = 1.234
    assert abs(G_new(x) - G_new(x + 2 * math.pi)) < 1e-9


def test_g_new_type_error():
    # строка → GNewError
    with pytest.raises(GNewError):
        G_new("not a number")
