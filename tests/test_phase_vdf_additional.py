# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_phase_vdf_additional.py
import hashlib
import pytest

from zilant_prime_core.vdf.phase_vdf import (  # :contentReference[oaicite:2]{index=2}
    VDFVerificationError,
    _validate_proof,
    _validate_seed,
    _validate_steps,
    generate_elc_vdf,
    verify_elc_vdf,
)


def test_validate_seed_bad_type():
    with pytest.raises(ValueError):
        _validate_seed("notbytes")


def test_validate_steps_bad():
    with pytest.raises(ValueError):
        _validate_steps(0)
    with pytest.raises(ValueError):
        _validate_steps(-5)


def test_validate_proof_bad_length():
    with pytest.raises(ValueError):
        _validate_proof(b"short")


def test_generate_and_verify_elc_vdf():
    seed = b"abc"
    proof = generate_elc_vdf(seed, 3)
    assert isinstance(proof, bytes) and len(proof) == hashlib.sha256().digest_size


def test_verify_elc_vdf_strict_behavior():
    seed = b"abc"
    wrong = b"\x00" * hashlib.sha256().digest_size
    # non-strict returns bool
    assert not verify_elc_vdf(seed, 1, wrong)
    # strict raises
    with pytest.raises(VDFVerificationError):
        verify_elc_vdf(seed, 1, wrong, strict=True)
