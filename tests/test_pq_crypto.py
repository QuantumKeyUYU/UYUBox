# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
from types import SimpleNamespace

import zilant_prime_core.utils.pq_crypto as pq


@pytest.mark.skipif(pq.kyber768 is None, reason="pqclean.kyber768 not installed")
def test_kyber768_generate_and_encapsulate_real():
    kem = pq.Kyber768KEM()
    pk, sk = kem.generate_keypair()
    ct, ss1 = kem.encapsulate(pk)
    ss2 = kem.decapsulate(sk, ct)
    assert ss1 == ss2
    key = pq.derive_key_pq(ss1)
    assert isinstance(key, bytes) and len(key) == 32


@pytest.mark.skipif(pq.dilithium2 is None, reason="pqclean.dilithium2 not installed")
def test_dilithium2_sign_and_verify_real():
    sig = pq.Dilithium2Signature()
    pk, sk = sig.generate_keypair()
    msg = b"hello"
    signature = sig.sign(sk, msg)
    assert sig.verify(pk, msg, signature) is True
    assert sig.verify(pk, msg + b"x", signature) is False


def test_kyber768_missing_dependency(monkeypatch):
    monkeypatch.setattr(pq, "kyber768", None)
    with pytest.raises(RuntimeError):
        pq.Kyber768KEM()


def test_dilithium2_missing_dependency(monkeypatch):
    monkeypatch.setattr(pq, "dilithium2", None)
    with pytest.raises(RuntimeError):
        pq.Dilithium2Signature()


def test_oqs_missing_dependency(monkeypatch):
    monkeypatch.setattr(pq, "oqs", None)
    with pytest.raises(RuntimeError):
        pq.OQSKyberKEM()


def test_signature_scheme_not_instantiable():
    with pytest.raises(TypeError):
        pq.SignatureScheme()


def test_kem_not_instantiable():
    with pytest.raises(TypeError):
        pq.KEM()


def test_derive_key_pq_type_error():
    with pytest.raises(TypeError):
        pq.derive_key_pq("not-bytes")  # type: ignore


def test_derive_key_pq_basic():
    key = pq.derive_key_pq(b"secret", length=16)
    assert isinstance(key, bytes)
    assert len(key) == 16


def test_kyber768_heavy_branches(monkeypatch):
    fake = SimpleNamespace(
        generate_keypair=lambda: (b"PUBL", b"PRIV"),
        encapsulate=lambda pub: (b"CTTT", b"SSSS"),
        decapsulate=lambda ct, sk: b"SSSS",
        CIPHERTEXT_SIZE=123,
    )
    monkeypatch.setattr(pq, "kyber768", fake)

    kem = pq.Kyber768KEM()
    assert kem.generate_keypair() == (b"PUBL", b"PRIV")
    assert kem.encapsulate(b"PUBL") == (b"CTTT", b"SSSS")
    assert kem.decapsulate(b"PRIV", b"CTTT") == b"SSSS"
    assert kem.ciphertext_length() == 123

    del fake.CIPHERTEXT_SIZE
    length = pq.Kyber768KEM.ciphertext_length()
    assert length == len(fake.encapsulate(fake.generate_keypair()[0])[0])


def test_dilithium2_heavy_branches(monkeypatch):
    fake = SimpleNamespace(
        generate_keypair=lambda: (b"PK", b"SK"),
        sign=lambda m, sk: b"SIGG",
        verify=lambda m, sig, pk: True,
    )
    monkeypatch.setattr(pq, "dilithium2", fake)

    sig = pq.Dilithium2Signature()
    assert sig.generate_keypair() == (b"PK", b"SK")
    assert sig.sign(b"m", b"SK") == b"SIGG"
    assert sig.verify(b"PK", b"m", b"SIGG") is True

    def bad_verify(m, sigg, pk):
        raise Exception("bad")

    fake.verify = bad_verify

    sig2 = pq.Dilithium2Signature()
    assert sig2.verify(b"PK", b"m", b"anything") is False


def test_oqskyberkem_heavy(monkeypatch):
    class DummyKEM:
        def __init__(self, alg):
            assert alg == "Kyber768"
            self.details = SimpleNamespace(length_ciphertext=77)

        def generate_keypair(self):
            return (b"OPK", b"OSK")

        def encapsulate(self, pk):
            return (b"OCT", b"OSS")

        def decapsulate(self, ct, sk):
            return b"OSS"

    fake = SimpleNamespace(KeyEncapsulation=lambda alg: DummyKEM(alg))
    monkeypatch.setattr(pq, "oqs", fake)

    kem = pq.OQSKyberKEM()
    assert kem.generate_keypair() == (b"OPK", b"OSK")
    assert kem.encapsulate(b"OPK") == (b"OCT", b"OSS")
    assert kem.decapsulate(b"OSK", b"OCT") == b"OSS"
    assert kem.ciphertext_length() == 77
