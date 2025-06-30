# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from zilant_prime_core.crypto.fractal_kdf import fractal_kdf


def test_fractal_kdf_basic():
    key = fractal_kdf(b"seed", depth=5)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_fractal_kdf_type_error():
    with pytest.raises(TypeError):
        fractal_kdf("not_bytes")  # type: ignore


def test_fractal_kdf_value_error():
    with pytest.raises(ValueError):
        fractal_kdf(b"seed", depth=0)
