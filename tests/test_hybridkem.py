import os
import types

os.environ.setdefault("ZILANT_ALLOW_ROOT", "1")
import zilant_prime_core.utils.pq_crypto as pq


def test_hybridkem_basic(monkeypatch):
    fake = types.SimpleNamespace(
        generate_keypair=lambda: (b"PK", b"SK"),
        encapsulate=lambda pk: (b"CT", b"SS"),
        decapsulate=lambda ct, sk: b"SS" if ct == b"CT" else b"BAD",
        CIPHERTEXT_SIZE=len(b"CT"),
    )
    monkeypatch.setattr(pq, "kyber768", fake)

    kem = pq.HybridKEM()
    pk_pq, sk_pq, pk_x, sk_x = kem.generate_keypair()
    ct_pq, _ss_pq, epk, _ss_x, shared1 = kem.encapsulate((pk_pq, pk_x))
    shared2 = kem.decapsulate((sk_pq, sk_x), (ct_pq, epk, b""))
    assert shared1 == shared2


def test_hybridkem_mismatch(monkeypatch):
    fake = types.SimpleNamespace(
        generate_keypair=lambda: (b"PK", b"SK"),
        encapsulate=lambda pk: (b"CT", b"SS"),
        decapsulate=lambda ct, sk: b"SS" if ct == b"CT" else b"BAD",
        CIPHERTEXT_SIZE=len(b"CT"),
    )
    monkeypatch.setattr(pq, "kyber768", fake)

    kem = pq.HybridKEM()
    pk_pq, sk_pq, pk_x, sk_x = kem.generate_keypair()
    ct_pq, _ss_pq, epk, _ss_x, shared1 = kem.encapsulate((pk_pq, pk_x))
    corrupted = ct_pq[:-1] + bytes([ct_pq[-1] ^ 1])
    shared2 = kem.decapsulate((sk_pq, sk_x), (corrupted, epk, b""))
    assert shared1 != shared2
