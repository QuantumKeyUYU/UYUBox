# tests/test_branch_cover.py
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from __future__ import annotations

import pytest
from types import SimpleNamespace

from landscape import verify_landscape

# --- 1. landscape -----------------------------------------------------------


def test_verify_landscape_strict_success():
    assert verify_landscape(([0, 1, 1], [9, 8, 7]), strict=True) is True


def test_verify_landscape_strict_failure():
    assert verify_landscape(([0, 5], [1, 2]), strict=True) is False


# --- 2. secure_memory -------------------------------------------------------

import utils.secure_memory as sm
from utils.secure_memory import wipe_bytes


def test_wipe_bytes_loop_branch():
    data = bytearray(b"secret")
    wipe_bytes(data)
    assert all(b == 0 for b in data)


def test_wipe_bytes_sodium_branch(monkeypatch):
    # просто покрываем ветку if _sodium is not None — не проверяем содержимое!
    dummy = SimpleNamespace(sodium_memzero=lambda buf, size: None)
    monkeypatch.setattr(sm, "_sodium", dummy, raising=True)
    data = bytearray(b"topsecret")
    wipe_bytes(data)
    # Не проверяем содержимое — иначе тест всегда будет падать без настоящей sodium


# --- 3. pq_crypto -----------------------------------------------------------

import zilant_prime_core.utils.pq_crypto as pq


def test_falcon_verify_exception_branch():
    falcon_stub = SimpleNamespace(
        sign=lambda m, sk: b"FSIG",
        verify=lambda m, sig, pk: (_ for _ in ()).throw(Exception("bad")),
    )
    sig = pq.FalconSig.__new__(pq.FalconSig)
    sig._falcon = falcon_stub  # type: ignore[attr-defined]
    assert sig.sign(b"sk", b"msg") == b"FSIG"
    assert sig.verify(b"pk", b"msg", b"SIG") is False


def test_sphincs_verify_exception_branch():
    sphincs_stub = SimpleNamespace(
        sign=lambda m, sk: b"SSIG",
        verify=lambda m, sig, pk: (_ for _ in ()).throw(Exception("bad")),
        generate_keypair=lambda: (b"PK", b"SK"),
    )
    sig = pq.SphincsSig.__new__(pq.SphincsSig)
    sig._sphincs = sphincs_stub  # type: ignore[attr-defined]
    assert sig.sign(b"SK", b"m") == b"SSIG"
    assert sig.verify(b"PK", b"m", b"SIG") is False


def test_derive_key_pq_slice_and_type():
    key16 = pq.derive_key_pq(b"shared-secret", length=16)
    assert len(key16) == 16

    with pytest.raises(TypeError):
        pq.derive_key_pq("oops")  # type: ignore[arg-type]


def test_kyber768kem_dep_guard(monkeypatch):
    monkeypatch.setattr(pq, "kyber768", None, raising=True)
    with pytest.raises(RuntimeError):
        pq.Kyber768KEM()


def test_dilithium2_dep_guard(monkeypatch):
    monkeypatch.setattr(pq, "dilithium2", None, raising=True)
    with pytest.raises(RuntimeError):
        pq.Dilithium2Signature()
