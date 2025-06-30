import pytest

from zilant_prime_core.utils.shard_secret import recover_secret, split_secret


def test_split_secret_invalid_parts():
    with pytest.raises(ValueError):
        split_secret(b"s", parts=0)


def test_split_secret_single_part():
    assert split_secret(b"foo", parts=1) == [b"foo"]


def test_recover_secret_empty():
    assert recover_secret([]) == b""


def test_split_and_recover_multiple():
    secret = b"abcdef"
    shards = split_secret(secret, parts=3)
    assert len(shards) == 3
    assert recover_secret(shards) == secret
