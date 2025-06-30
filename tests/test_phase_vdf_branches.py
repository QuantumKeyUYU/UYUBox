# tests/test_phase_vdf_branches.py

# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import hashlib
import pytest

from zilant_prime_core.vdf.phase_vdf import (
    VDFVerificationError,
    _validate_proof,
    _validate_seed,
    _validate_steps,
    generate_elc_vdf,
    generate_landscape,
    generate_posw_sha256,
    prove_posw_sha256,
    verify_elc_vdf,
    verify_landscape,
    verify_posw_sha256,
)


def test_validate_seed_accepts_bytes_and_bytearray_and_errors():
    with pytest.raises(ValueError):
        _validate_seed("notbytes")
    assert _validate_seed(b"x") == b"x"
    assert _validate_seed(bytearray(b"y")) == b"y"


def test_validate_steps_errors_and_accepts():
    for bad in (0, -1, 1.5, "1"):
        with pytest.raises(ValueError):
            _validate_steps(bad)
    assert _validate_steps(1) == 1


def test_validate_proof_errors_for_non_bytes_and_wrong_length():
    with pytest.raises(ValueError):
        _validate_proof("notbytes")
    too_short = b"\x00" * (hashlib.sha256().digest_size - 1)
    with pytest.raises(ValueError):
        _validate_proof(too_short)


def test_aliases_equivalent_to_generate_elc():
    seed = b"seed"
    steps = 4
    base = generate_elc_vdf(seed, steps)
    assert generate_posw_sha256(seed, steps) == base
    assert prove_posw_sha256(seed, steps) == base
    assert generate_landscape(seed, steps) == base


def test_verify_elc_posw_landscape_true_false():
    seed = b"seed"
    steps = 3
    proof = generate_elc_vdf(seed, steps)

    # elc
    assert verify_elc_vdf(seed, steps, proof) is True
    assert verify_elc_vdf(seed, steps, proof[:-1] + b"\x00") is False

    # posw: order is (seed, proof, steps)
    assert verify_posw_sha256(seed, proof, steps) is True
    assert verify_posw_sha256(seed, proof, steps + 1) is False

    # landscape: same as elc signature
    assert verify_landscape(seed, steps, proof) is True
    assert verify_landscape(seed, steps + 1, proof) is False


def test_verify_strict_mode_raises():
    seed = b"hello"
    steps = 1
    bad_proof = b"\x00" * hashlib.sha256().digest_size
    with pytest.raises(VDFVerificationError):
        verify_elc_vdf(seed, steps, bad_proof, strict=True)


def test_generate_and_verify_elc_roundtrip():
    seed = b"abc"
    for s in (1, 5, 10):
        proof = generate_elc_vdf(seed, s)
        assert verify_elc_vdf(seed, s, proof) is True
