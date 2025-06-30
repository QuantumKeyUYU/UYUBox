# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

from src.landscape import generate_landscape, verify_landscape


def test_generate_landscape_invalid_size():
    with pytest.raises(ValueError):
        generate_landscape(0)
    with pytest.raises(ValueError):
        generate_landscape(-10)


def test_generate_landscape_strict_false_values():
    clauses, salts = generate_landscape(10, strict=False)
    assert len(clauses) == 10 and len(salts) == 10
    assert all(0 <= c <= 255 for c in clauses)
    assert all(isinstance(s, int) for s in salts)


def test_generate_landscape_strict_true_values():
    clauses, salts = generate_landscape(10, strict=True)
    assert all(c in (0, 1) for c in clauses)


def test_verify_landscape_invalid_type():
    with pytest.raises(ValueError):
        verify_landscape("not a tuple")
    with pytest.raises(ValueError):
        verify_landscape((1, 2))  # не списки внутри
    with pytest.raises(ValueError):
        verify_landscape(([1, 2], "not a list"))  # второй элемент не список


def test_verify_landscape_mismatched_lengths():
    with pytest.raises(ValueError):
        verify_landscape(([], [1, 2]))
    with pytest.raises(ValueError):
        verify_landscape(([1, 2], []))


def test_verify_landscape_bad_elements():
    assert not verify_landscape(([1, "x"], [1, 2]))
    assert not verify_landscape(([2, 0], [1, 1]), strict=True)
    assert not verify_landscape(([0, 1], [1, None]), strict=False)


def test_verify_landscape_empty_lists():
    # zip не заходит, типы верные — должно быть True
    assert verify_landscape(([], []), strict=False)
    assert verify_landscape(([], []), strict=True)


def test_verify_landscape_non_int_values():
    # В одном из списков не int — должно вернуть False
    assert not verify_landscape(([1, "not-int"], [2, 3]), strict=False)
    assert not verify_landscape(([1, 2], [3, "not-int"]), strict=False)


def test_verify_landscape_strict_mode_invalid_value():
    # strict True, но не 0/1 — return False
    assert not verify_landscape(([2, 1], [1, 2]), strict=True)
    assert not verify_landscape(([0, 4], [1, 1]), strict=True)
