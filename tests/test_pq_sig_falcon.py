import os
import sys
import types

os.environ.setdefault("ZILANT_ALLOW_ROOT", "1")
import zilant_prime_core.utils.pq_crypto as pq


def test_falcon_basic(monkeypatch):
    fake = types.SimpleNamespace(
        generate_keypair=lambda: (b"PK", b"SK"),
        sign=lambda m, sk: b"SIG",
        verify=lambda m, sig, pk: True,
    )
    monkeypatch.setitem(sys.modules, "pqclean.branchfree", types.SimpleNamespace(falcon1024=fake))
    monkeypatch.setitem(sys.modules, "pqclean", types.SimpleNamespace(falcon1024=fake))
    sig = pq.FalconSig()
    pk, sk = sig.generate_keypair()
    s = sig.sign(sk, b"m")
    assert sig.verify(pk, b"m", s)
