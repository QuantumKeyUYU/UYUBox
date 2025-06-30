# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

# tests/test_vdf_property.py
import sys

# На Windows Hypothesis падает из-за внутреннего бага с sys.modules
if sys.platform.startswith("win"):
    pytest.skip(
        "Skipping VDF property-based tests on Windows due to Hypothesis sys.modules issue",
        allow_module_level=True,
    )

from hypothesis import given
from hypothesis import strategies as st

import zilant_prime_core.vdf as vdf_mod


@given(
    seed=st.binary(min_size=1, max_size=64),
    steps=st.integers(min_value=1, max_value=100),
)
def test_posw_roundtrip(seed, steps):
    proof, ok = vdf_mod.posw(seed, steps)
    assert ok is True
    assert vdf_mod.check_posw(proof, seed, steps) is True


@given(seed=st.binary(), steps=st.integers(max_value=0))
def test_posw_invalid_steps(seed, steps):
    with pytest.raises(ValueError):
        vdf_mod.posw(seed, steps)


@given(
    seed=st.binary(min_size=1),
    steps=st.integers(min_value=1, max_value=100),
    bad_proof=st.binary(),
)
def test_posw_bad_proof_returns_false(seed, steps, bad_proof):
    # Генерируем правильное доказательство, но затем портим его на входе
    proof, ok = vdf_mod.posw(seed, steps)
    assert ok is True
    # сурово затираем
    bad = bad_proof + proof
    assert vdf_mod.check_posw(bad, seed, steps) is False
