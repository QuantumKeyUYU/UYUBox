import json
import pytest
from pathlib import Path

from container import pack_file, unpack_file


@pytest.fixture()
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "data.bin"
    p.write_bytes(b"data")
    return p


@pytest.fixture()
def password() -> bytes:
    return b"x" * 32


def _corrupt_header(data: bytes, mutate: callable) -> bytes:
    sep_idx = data.find(b"\n\n")
    header = json.loads(data[:sep_idx].decode("utf-8"))
    mutate(header)
    new_header = json.dumps(header).encode("utf-8")
    return new_header + b"\n\n" + data[sep_idx + 2 :]


def test_unpack_no_separator(tmp_path: Path, password: bytes) -> None:
    bad = tmp_path / "no_sep.zil"
    bad.write_bytes(b"dummy-header" + b"cipher")
    out = tmp_path / "out"
    with pytest.raises(ValueError):
        unpack_file(bad, out, password)


def test_unpack_wrong_magic(tmp_path: Path, sample_file: Path, password: bytes) -> None:
    good = tmp_path / "good.zil"
    pack_file(sample_file, good, password)
    data = good.read_bytes()

    corrupt = tmp_path / "bad_magic.zil"
    corrupt.write_bytes(
        _corrupt_header(
            data,
            lambda h: h.update({"magic": "BAD"}),
        )
    )
    out = tmp_path / "out"
    with pytest.raises(ValueError):
        unpack_file(corrupt, out, password)


def test_unpack_wrong_version(tmp_path: Path, sample_file: Path, password: bytes) -> None:
    good = tmp_path / "good.zil"
    pack_file(sample_file, good, password)
    data = good.read_bytes()
    corrupt = tmp_path / "bad_ver.zil"
    corrupt.write_bytes(_corrupt_header(data, lambda h: h.update({"version": 999})))
    out = tmp_path / "out"
    with pytest.raises(ValueError):
        unpack_file(corrupt, out, password)


def test_unpack_checksum_mismatch(tmp_path: Path, sample_file: Path, password: bytes) -> None:
    good = tmp_path / "good.zil"
    pack_file(sample_file, good, password)
    data = good.read_bytes()
    corrupt = tmp_path / "bad_checksum.zil"
    corrupt.write_bytes(_corrupt_header(data, lambda h: h.update({"checksum_hex": "0" * 64})))
    out = tmp_path / "out"
    with pytest.raises(ValueError):
        unpack_file(corrupt, out, password)


def test_unpack_size_mismatch(tmp_path: Path, sample_file: Path, password: bytes) -> None:
    good = tmp_path / "good.zil"
    pack_file(sample_file, good, password)
    data = good.read_bytes()
    corrupt = tmp_path / "bad_size.zil"
    corrupt.write_bytes(_corrupt_header(data, lambda h: h.update({"orig_size": 99})))
    out = tmp_path / "out"
    with pytest.raises(ValueError):
        unpack_file(corrupt, out, password)
