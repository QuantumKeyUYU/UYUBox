# tests/test_pqcrypto.py

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from types import SimpleNamespace

import pqcrypto as pq


def test_hybrid_encrypt_decrypt(monkeypatch):
    class DummyHybrid:
        def encapsulate(self, recipient_pk):
            # ct_pq, _ss, epk, _ek, shared
            return b"CT", None, b"X" * 32, None, b"KEY"

        def decapsulate(self, recipient_sk, ct_tuple):
            # модуль передаёт (ct_pq, epk, b"")
            assert ct_tuple == (b"CT", b"X" * 32, b"")
            return b"KEY"

    class DummyAEAD:
        def __init__(self, key):
            pass

        def encrypt(self, nonce, pt, aad):
            return pt[::-1]

        def decrypt(self, nonce, ct, aad):
            return ct[::-1]

    monkeypatch.setattr(pq, "HybridKEM", DummyHybrid)
    monkeypatch.setattr(pq, "ChaCha20Poly1305", DummyAEAD)
    monkeypatch.setattr(pq.os, "urandom", lambda n: b"N" * n)

    pubkeys = (b"pk1", b"pk2")
    plaintext = b"DATA"
    aad = b"AAD"

    header, ct = pq.hybrid_encrypt(pubkeys, plaintext, aad)
    assert isinstance(header, bytes) and ct == plaintext[::-1]

    rec = pq.hybrid_decrypt((b"sk1", b"sk2"), header, ct, aad)
    assert rec == plaintext


def test_dual_sign_no_dilithium():
    priv = ed25519.Ed25519PrivateKey.generate()
    sk_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # без pqclean.dilithium3 должен быть RuntimeError
    with pytest.raises(RuntimeError):
        pq.dual_sign(b"MSG", sk_bytes, b"DILSK")


def test_dual_sign_and_verify_with_dummy(monkeypatch):
    priv = ed25519.Ed25519PrivateKey.generate()
    sk_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    dummy = SimpleNamespace(sign=lambda msg, sk: b"PQSIG")
    monkeypatch.setattr(pq, "dilithium3", dummy)

    sig = pq.dual_sign(b"MSG", sk_bytes, b"PQSK")
    assert isinstance(sig, bytes) and len(sig) > 64

    # проверка гибридной верификации
    assert isinstance(pq.dual_verify(b"MSG", sig, pub_bytes, b"PQPK"), bool)
    assert not pq.dual_verify(b"BAD", sig, pub_bytes, b"PQPK")


def test_dual_verify_short_sig():
    assert not pq.dual_verify(b"m", b"short", b"pk", b"pk")
