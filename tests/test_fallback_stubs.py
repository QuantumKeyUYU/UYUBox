import pytest

from shard_secret import combine_signatures
from zilant_prime_core.utils.pq_crypto import derive_key_pq


def test_derive_key_pq_invalid():
    with pytest.raises(TypeError):
        derive_key_pq("notbytes")  # type: ignore[arg-type]


def test_derive_key_pq_length():
    key = derive_key_pq(b"secret", length=16)
    assert len(key) == 16


def test_combine_signatures_single():
    assert combine_signatures([b"sig"]) == b"sig"
