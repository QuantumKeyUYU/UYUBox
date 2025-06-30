# tests/test_vdf.py

import hashlib
import pytest
import sys
import time

from zilant_prime_core.vdf.vdf import generate_posw_sha256, verify_posw_sha256


@pytest.mark.parametrize("steps", [1, 2, 10])
def test_generate_and_verify_roundtrip(steps):
    seed = b"test-seed"
    proof = generate_posw_sha256(seed, steps)
    # Proof is a SHA256 digest
    assert isinstance(proof, bytes)
    assert len(proof) == hashlib.sha256().digest_size

    # Correct proof verifies
    assert verify_posw_sha256(seed, proof, steps) is True

    # Tampered proof fails
    tampered = bytearray(proof)
    tampered[0] ^= 0xFF
    assert verify_posw_sha256(seed, bytes(tampered), steps) is False

    # Wrong steps or seed fails
    assert verify_posw_sha256(seed, proof, steps + 1) is False
    assert verify_posw_sha256(b"wrong-seed", proof, steps) is False


@pytest.mark.parametrize("invalid_steps", [0, -5, None])
def test_invalid_steps_raise(invalid_steps):
    with pytest.raises(ValueError, match="Steps must be a positive integer"):
        generate_posw_sha256(b"seed", invalid_steps)  # type: ignore
    with pytest.raises(ValueError, match="Steps must be a positive integer"):
        verify_posw_sha256(b"seed", b"\x00" * hashlib.sha256().digest_size, invalid_steps)  # type: ignore


def test_invalid_seed_type_raises():
    with pytest.raises(ValueError, match="Seed must be bytes"):
        generate_posw_sha256("not-bytes", 1)  # type: ignore
    with pytest.raises(ValueError, match="Seed must be bytes"):
        verify_posw_sha256("not-bytes", b"\x00" * hashlib.sha256().digest_size, 1)  # type: ignore


def test_proof_length_mismatch():
    seed = b"seed"
    steps = 5
    good_proof = generate_posw_sha256(seed, steps)
    # Too short
    assert verify_posw_sha256(seed, good_proof[:-1], steps) is False
    # Too long
    assert verify_posw_sha256(seed, good_proof + b"\x00", steps) is False


@pytest.mark.skipif(sys.platform.startswith("win"), reason="Flaky on Windows")
def test_performance_characteristics():
    seed = b"perf-test"
    steps = 100_000

    t0 = time.perf_counter()
    proof = generate_posw_sha256(seed, steps)
    dt_gen = time.perf_counter() - t0

    t1 = time.perf_counter()
    ok = verify_posw_sha256(seed, proof, steps)
    dt_ver = time.perf_counter() - t1

    assert ok is True
    # Verify should not be significantly slower than generate
    assert dt_ver / dt_gen < 2.0
