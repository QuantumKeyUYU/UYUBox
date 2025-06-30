# tests/test_metadata_branches.py

# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT


import pytest

from zilant_prime_core.container.metadata import (
    Metadata,
    MetadataError,
    deserialize_metadata,
    new_meta_for_file,
    serialize_metadata,
)


def test_metadata_init_requires_both_filename_and_size():
    with pytest.raises(MetadataError):
        Metadata()  # ни filename, ни size
    with pytest.raises(MetadataError):
        Metadata(filename="a.txt")  # нет size
    with pytest.raises(MetadataError):
        Metadata(size=10)  # нет filename


def test_from_mapping_missing_keys_raises():
    # from_mapping требует и filename (или file) и size
    with pytest.raises(MetadataError):
        Metadata.from_mapping({"filename": "a.txt"})
    with pytest.raises(MetadataError):
        Metadata.from_mapping({"size": 5})


def test_new_meta_for_file(tmp_path):
    f = tmp_path / "foo.bin"
    payload = b"12345"
    f.write_bytes(payload)
    m = new_meta_for_file(f)
    assert m.filename == "foo.bin"
    assert m.size == len(payload)


def test_serialize_deserialize_roundtrip_and_error_cases():
    # 1) Metadata → bytes → dict
    m = Metadata(filename="x", size=1, extra={"b": b"\x01\x02"})
    raw = serialize_metadata(m)
    d = deserialize_metadata(raw)
    assert d["filename"] == "x"
    assert d["size"] == 1
    assert isinstance(d["b"], str)  # b64→str

    # 2) mapping as input
    raw2 = serialize_metadata({"foo": "bar", "num": 7, "blob": b"\x03"})
    d2 = deserialize_metadata(raw2)
    assert d2["foo"] == "bar"
    assert d2["num"] == 7
    assert isinstance(d2["blob"], str)

    # 3) unsupported input type to serialize_metadata
    with pytest.raises(MetadataError):
        serialize_metadata(123)

    # 4) nested unsupported value
    with pytest.raises(MetadataError):
        serialize_metadata({"a": [object()]})

    # 5) invalid raw bytes for deserialize_metadata
    with pytest.raises(MetadataError):
        deserialize_metadata(b"not a json")
