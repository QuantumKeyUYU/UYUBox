# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_landscape.py

import pytest

from src.landscape import generate_landscape, verify_landscape


@pytest.mark.parametrize("strict", [False, True])
def test_generate_and_verify_landscape(strict):
    # Генерируем «пейзаж»
    landscape = generate_landscape(size=5, strict=strict)
    # Проверяем, что verify не выбрасывает ошибки
    assert verify_landscape(landscape, strict=strict)


def test_verify_landscape_invalid_input():
    # Передаём совсем не то
    with pytest.raises(ValueError):
        verify_landscape("not-a-landscape", strict=False)
