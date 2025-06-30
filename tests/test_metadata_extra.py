# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_metadata_extra.py

import json
import pytest

from zilant_prime_core.container.metadata import (
    Metadata,
    MetadataError,
    deserialize_metadata,
    new_meta_for_file,
    serialize_metadata,
)
from zilant_prime_core.utils.formats import from_b64


def test_new_meta_for_file(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("xyz")
    m = new_meta_for_file(f)
    assert m.filename == "a.txt"
    assert m.size == 3


def test_serialize_deserialize_roundtrip_bytes_extra():
    m = Metadata("n", 5, extra={"blob": b"\x01\x02\xff"})
    b = serialize_metadata(m)
    d = json.loads(b.decode("utf-8"))
    assert d["filename"] == "n"
    assert d["size"] == 5
    assert isinstance(d["blob"], str)
    assert from_b64(d["blob"]) == b"\x01\x02\xff"

    d2 = deserialize_metadata(b)
    assert d2 == d


def test_serialize_plain_dict():
    d = {"foo": "bar", "num": 7}
    b = serialize_metadata(d)
    assert b == json.dumps(d).encode("utf-8")


def test_serialize_unsupported_type():
    with pytest.raises(MetadataError):
        serialize_metadata(12345)


def test_serialize_unserializable_extra():
    m = Metadata("n", 0, extra={"bad": object()})
    with pytest.raises(MetadataError):
        serialize_metadata(m)


def test_deserialize_invalid_bytes():
    with pytest.raises(MetadataError):
        deserialize_metadata(b"\xff\xfe\xfa")
