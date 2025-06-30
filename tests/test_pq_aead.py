import pytest
from cryptography.exceptions import InvalidTag

from aead import PQAEAD
from zilant_prime_core.utils import pq_crypto


@pytest.mark.skipif(pq_crypto.kyber768 is None, reason="pqclean.kyber768 not installed")
def test_pq_aead_roundtrip():
    kem = pq_crypto.Kyber768KEM()
    pk, sk = kem.generate_keypair()
    plaintext = b"PQ secret"
    combined = PQAEAD.encrypt(pk, plaintext, b"head")
    recovered = PQAEAD.decrypt(sk, combined, b"head")
    assert recovered == plaintext


@pytest.mark.skipif(pq_crypto.kyber768 is None, reason="pqclean.kyber768 not installed")
def test_pq_aead_bad_key():
    kem = pq_crypto.Kyber768KEM()
    pk, sk = kem.generate_keypair()
    data = PQAEAD.encrypt(pk, b"m", b"")
    bad_sk = bytearray(sk)
    if bad_sk:
        bad_sk[0] ^= 0x01
    with pytest.raises(InvalidTag):
        PQAEAD.decrypt(bytes(bad_sk), data, b"")
