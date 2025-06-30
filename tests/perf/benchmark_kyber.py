import pytest
import time

from zilant_prime_core.utils.pq_crypto import Kyber768KEM


@pytest.mark.perf
@pytest.mark.skipif(Kyber768KEM is None, reason="pqclean not installed")
def test_kyber_decapsulation_speed():
    kem = Kyber768KEM()
    pk, sk = kem.generate_keypair()
    ct, _ = kem.encapsulate(pk)
    start = time.time()
    kem.decapsulate(sk, ct)
    assert time.time() - start < 1
