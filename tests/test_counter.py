import pytest

from zilant_prime_core.counter import DistributedCounter, SecurityError


def test_increment_and_verify(tmp_path):
    path = tmp_path / "ctr.bin"
    ctr = DistributedCounter(path, b"a" * 32)
    assert ctr.increment() == 1
    assert ctr.increment() == 2
    assert ctr.verify_and_load() == 2


def test_tamper_detection(tmp_path):
    path = tmp_path / "ctr.bin"
    ctr = DistributedCounter(path, b"b" * 32)
    ctr.increment()
    raw = path.read_bytes()
    # flip a byte
    path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(SecurityError):
        ctr.verify_and_load()
