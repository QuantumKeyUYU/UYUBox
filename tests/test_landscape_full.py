# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

from landscape import generate_landscape, generate_sat, verify_landscape


def test_generate_sat_invalid_variables():
    with pytest.raises(ValueError):
        generate_sat(0, 1)
    with pytest.raises(ValueError):
        generate_sat(-1, 1)
    with pytest.raises(ValueError):
        generate_sat("a", 1)


def test_generate_sat_invalid_density():
    with pytest.raises(ValueError):
        generate_sat(1, -0.1)
    with pytest.raises(ValueError):
        generate_sat(1, "a")


def test_generate_landscape_invalid_size():
    with pytest.raises(ValueError):
        generate_landscape(0)
    with pytest.raises(ValueError):
        generate_landscape(-1)
    with pytest.raises(ValueError):
        generate_landscape("a")


def test_generate_landscape_strict_false_values():
    c, s = generate_landscape(3, strict=False)
    assert isinstance(c, list) and isinstance(s, list)
    assert len(c) == 3 and len(s) == 3


def test_generate_landscape_strict_true_values():
    c, s = generate_landscape(3, strict=True)
    assert all(x in (0, 1) for x in c)
    assert all(isinstance(x, int) for x in s)


def test_verify_landscape_invalid_input():
    with pytest.raises(ValueError):
        verify_landscape("not a tuple")
    with pytest.raises(ValueError):
        verify_landscape(([], [1, 2, 3]))  # длины не совпадают


def test_verify_landscape_mismatched_lengths():
    with pytest.raises(ValueError):
        verify_landscape(([1, 2], [1]))


def test_verify_landscape_bad_elements():
    result = verify_landscape(([1, "a"], [1, 2]))
    assert result is False
    result = verify_landscape(([1, 2], [1, "b"]))
    assert result is False


def test_verify_landscape_empty_lists():
    assert verify_landscape(([], [])) is True


def test_verify_landscape_non_int_values():
    result = verify_landscape(([1.5], [1.5]))
    assert result is False


def test_verify_landscape_strict_mode_invalid_value():
    result = verify_landscape(([1, 2], [1, 2]), strict=True)
    assert result is False


def test_generate_sat_basic():
    f = generate_sat(3, 1.0)
    assert isinstance(f, list)
    assert all(isinstance(clause, list) for clause in f)


def test_generate_landscape_basic():
    c, s = generate_landscape(5)
    assert len(c) == 5 and len(s) == 5
    c2, s2 = generate_landscape(5, strict=True)
    assert all(x in (0, 1) for x in c2)
