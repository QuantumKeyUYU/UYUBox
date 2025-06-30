import os
import pytest
from cryptography.exceptions import InvalidTag
from pathlib import Path

from container import pack_file, unpack_file
from zilant_prime_core.utils import pq_crypto


@pytest.fixture()
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "hello.txt"
    p.write_bytes(b"Hello, Zilant!")
    return p


@pytest.fixture()
def password() -> bytes:
    return os.urandom(32)


def test_pack_and_unpack_roundtrip(tmp_path: Path, sample_file: Path, password: bytes) -> None:
    container = tmp_path / "hello.zil"
    pack_file(sample_file, container, password)
    assert container.exists()

    out_file = tmp_path / "restored.txt"
    unpack_file(container, out_file, password)
    assert out_file.exists()
    assert out_file.read_bytes() == sample_file.read_bytes()


def test_unpack_with_bad_password(tmp_path: Path, sample_file: Path) -> None:
    container = tmp_path / "hello.zil"
    pack_file(sample_file, container, os.urandom(32))
    out_file = tmp_path / "broken.txt"
    with pytest.raises(InvalidTag):
        unpack_file(container, out_file, os.urandom(32))
    assert not out_file.exists()


@pytest.mark.skipif(pq_crypto.kyber768 is None, reason="pqclean.kyber768 not installed")
def test_pack_unpack_pq_roundtrip(tmp_path: Path, sample_file: Path):
    kem = pq_crypto.Kyber768KEM()
    pk, sk = kem.generate_keypair()
    container = tmp_path / "pq.zil"
    pack_file(sample_file, container, b"", pq_public_key=pk)
    out_file = tmp_path / "out.txt"
    unpack_file(container, out_file, b"", pq_private_key=sk)
    assert out_file.read_bytes() == sample_file.read_bytes()
