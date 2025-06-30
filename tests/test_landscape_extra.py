# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_landscape_extra.py

import pytest

from landscape import generate_sat


def test_generate_sat_invalid_args():
    with pytest.raises(ValueError):
        generate_sat(0, 1.0)
    with pytest.raises(ValueError):
        generate_sat(3, -0.1)
    with pytest.raises(ValueError):
        generate_sat("3", 1.0)


def test_generate_sat_clause_structure():
    from random import seed

    seed(123)
    formula = generate_sat(5, 2.0)
    # Expect exactly 10 clauses
    assert isinstance(formula, list)
    assert len(formula) == 10
    for clause in formula:
        assert isinstance(clause, list)
        assert 1 <= len(clause) <= 3
        for lit in clause:
            assert abs(lit) in {1, 2, 3, 4, 5}
