# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import hashlib
import pytest

from zilant_prime_core.vdf.vdf import generate_posw_sha256, prove_posw_sha256, verify_posw_sha256


def test_generate_invalid_seed_type():
    with pytest.raises(ValueError):
        generate_posw_sha256("not-bytes", steps=1)


def test_generate_invalid_steps():
    with pytest.raises(ValueError):
        generate_posw_sha256(b"x", steps=0)
    with pytest.raises(ValueError):
        generate_posw_sha256(b"x", steps=-5)
    with pytest.raises(ValueError):
        generate_posw_sha256(b"x", steps=1.5)


def test_verify_invalid_seed_and_steps():
    with pytest.raises(ValueError):
        verify_posw_sha256("no", b"", steps=1)
    with pytest.raises(ValueError):
        verify_posw_sha256(b"x", b"", steps=0)


def test_verify_wrong_proof_length():
    data = b"xyz"
    proof = hashlib.sha256(b"").digest()[:-1]
    assert verify_posw_sha256(data, proof, steps=1) is False


def test_verify_mismatch_proof():
    data = b"abc"
    wrong = b"\x00" * 32
    assert verify_posw_sha256(data, wrong, steps=1) is False


def test_verify_correct_and_alias():
    data = b"foo"
    proof = generate_posw_sha256(data, 2)
    assert verify_posw_sha256(data, proof, steps=2)
    # alias
    assert prove_posw_sha256(data, 2) == proof
