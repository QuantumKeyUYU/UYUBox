import os
import sys
import types

os.environ.setdefault("ZILANT_ALLOW_ROOT", "1")
import zilant_prime_core.utils.pq_crypto as pq


def test_sphincs_basic(monkeypatch):
    fake = types.SimpleNamespace(
        generate_keypair=lambda: (b"PK", b"SK"),
        sign=lambda m, sk: b"SIG",
        verify=lambda m, sig, pk: True,
    )
    monkeypatch.setitem(sys.modules, "pqclean.branchfree", types.SimpleNamespace(sphincsplus_sha256_128f_simple=fake))
    monkeypatch.setitem(sys.modules, "pqclean", types.SimpleNamespace(sphincsplus_sha256_128f_simple=fake))
    sig = pq.SphincsSig()
    pk, sk = sig.generate_keypair()
    s = sig.sign(sk, b"m")
    assert sig.verify(pk, b"m", s)
