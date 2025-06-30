# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import hashlib
import pytest

from zilant_prime_core.vdf.phase_vdf import generate_elc_vdf, verify_elc_vdf


def test_elc_vdf_basic():
    seed = b"test_seed"
    steps = 100
    proof = generate_elc_vdf(seed, steps)
    # Должен вернуть bytes длины sha256
    assert isinstance(proof, bytes)
    assert len(proof) == hashlib.sha256().digest_size
    # И проверка должна пройти
    assert verify_elc_vdf(seed, steps, proof)


def test_elc_vdf_invalid_steps():
    # Шагов должно быть > 0
    with pytest.raises(ValueError):
        generate_elc_vdf(b"seed", 0)
    with pytest.raises(ValueError):
        verify_elc_vdf(b"seed", 0, b"\x00" * hashlib.sha256().digest_size)


def test_elc_vdf_invalid_types():
    # Неправильный тип seed/proof
    with pytest.raises(ValueError):
        generate_elc_vdf("not-bytes", 10)  # type: ignore
    with pytest.raises(ValueError):
        verify_elc_vdf(b"seed", 10, "not-bytes")  # type: ignore


def test_elc_vdf_tampered_proof():
    seed = b"test_seed"
    steps = 50
    proof = generate_elc_vdf(seed, steps)
    tampered = bytearray(proof)
    tampered[0] ^= 0xFF
    # После подмены proof верификация должна упасть (вернуть False)
    assert not verify_elc_vdf(seed, steps, bytes(tampered))
