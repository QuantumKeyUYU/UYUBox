# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from zilant_prime_core.crypto.fractal_kdf import fractal_kdf


def test_fractal_kdf_type_error():
    # Должно кидать TypeError если нет аргументов
    with pytest.raises(TypeError):
        fractal_kdf()
