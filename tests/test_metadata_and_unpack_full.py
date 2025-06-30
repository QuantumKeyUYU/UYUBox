# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import json
import os
import pytest

from zilant_prime_core.container.metadata import (
    Metadata,
    MetadataError,
    deserialize_metadata,
    new_meta_for_file,
    serialize_metadata,
)
from zilant_prime_core.container.unpack import PackError, UnpackError, pack, unpack
from zilant_prime_core.crypto.aead import DEFAULT_NONCE_LENGTH
from zilant_prime_core.crypto.kdf import DEFAULT_SALT_LENGTH

# —————————————————————————————————————————————
# METADATA
# —————————————————————————————————————————————


def test_metadata_init_and_repr():
    m = Metadata(filename="a.txt", size=123, extra={"foo": "bar"})
    assert m.filename == "a.txt"
    assert m.size == 123
    assert m.extra == {"foo": "bar"}
    assert "a.txt" in repr(m)
    d = m.to_dict()
    assert d["filename"] == "a.txt" and d["size"] == 123


def test_metadata_init_errors():
    with pytest.raises(MetadataError):
        Metadata(size=1)
    with pytest.raises(MetadataError):
        Metadata(filename="a.txt")
    with pytest.raises(MetadataError):
        Metadata()


def test_from_mapping_and_roundtrip():
    base = {"filename": "z", "size": 2, "x": 42}
    m = Metadata.from_mapping(base)
    assert m.filename == "z" and m.size == 2 and m.extra == {"x": 42}
    blob = serialize_metadata(m)
    restored = deserialize_metadata(blob)
    # restore→dict compares keys
    assert restored == base


def test_json_ready_and_unsupported_types():
    # bytes→base64 roundtrip
    m = Metadata("b", 3, extra={"blob": b"\x00\xff"})
    blob = serialize_metadata(m)
    d = json.loads(blob.decode())
    assert isinstance(d["blob"], str)
    assert d["blob"] != b"\x00\xff"
    # unsupported top-level
    with pytest.raises(MetadataError):
        serialize_metadata(123)
    # unsupported nested
    with pytest.raises(MetadataError):
        serialize_metadata({"filename": "f", "size": 1, "bad": object()})


def test_serialize_error_propagation(monkeypatch):
    def bad_dumps(*a, **k):
        raise TypeError("boom")

    monkeypatch.setattr(json, "dumps", bad_dumps)
    with pytest.raises(MetadataError):
        serialize_metadata({"filename": "f", "size": 1})


def test_new_meta_for_file(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"12345")
    m = new_meta_for_file(f)
    assert m.filename == "x.txt" and m.size == 5


# —————————————————————————————————————————————
# PACK / UNPACK
# —————————————————————————————————————————————


def test_pack_and_unpack_cycle(tmp_path):
    src = tmp_path / "a.bin"
    data = os.urandom(16)
    src.write_bytes(data)
    container = pack(src, password="pw")
    out_dir = tmp_path / "out"
    out_file = unpack(container, out_dir, "pw")
    assert out_file.read_bytes() == data
    # second unpack → FileExistsError
    with pytest.raises(FileExistsError):
        unpack(container, out_dir, "pw")


def test_pack_errors(tmp_path):
    with pytest.raises(PackError):
        pack(tmp_path / "nope", "pw")
    d = tmp_path / "sub"
    d.mkdir()
    with pytest.raises(PackError):
        pack(d, "pw")


def test_unpack_malformed_containers(tmp_path):
    # too short
    with pytest.raises(UnpackError):
        unpack(b"\x00\x00\x00", tmp_path, "pw")
    # meta too short
    c = b"\x00\x00\x00\x05abcd"
    with pytest.raises(UnpackError):
        unpack(c, tmp_path, "pw")
    # missing salt/nonce
    # build a valid metadata header, then stop
    from zilant_prime_core.container.metadata import serialize_metadata

    m = {"filename": "f", "size": 1}
    mb = serialize_metadata(m)
    header = len(mb).to_bytes(4, "big") + mb
    with pytest.raises(UnpackError):
        unpack(header, tmp_path, "pw")


def test_unpack_invalid_fields(tmp_path):
    from zilant_prime_core.container.metadata import serialize_metadata

    # missing filename
    m1 = {"size": 1}
    mb1 = serialize_metadata(m1)
    salt = os.urandom(DEFAULT_SALT_LENGTH)
    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    ct = os.urandom(32)
    c1 = len(mb1).to_bytes(4, "big") + mb1 + salt + nonce + ct
    with pytest.raises(UnpackError):
        unpack(c1, tmp_path, "pw")
    # bad size
    m2 = {"filename": "f", "size": "bad"}
    mb2 = serialize_metadata(m2)
    c2 = len(mb2).to_bytes(4, "big") + mb2 + salt + nonce + ct
    with pytest.raises(UnpackError):
        unpack(c2, tmp_path, "pw")


def test_unpack_bad_tag(tmp_path):
    from zilant_prime_core.container.metadata import serialize_metadata

    m = {"filename": "f", "size": 0}
    mb = serialize_metadata(m)
    salt = os.urandom(DEFAULT_SALT_LENGTH)
    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    ct = b"\x00" * DEFAULT_NONCE_LENGTH  # too short→fail tag
    c = len(mb).to_bytes(4, "big") + mb + salt + nonce + ct
    with pytest.raises(UnpackError):
        unpack(c, tmp_path, "pw")
