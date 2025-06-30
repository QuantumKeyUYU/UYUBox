# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

from zilant_prime_core.container.metadata import MetadataError, deserialize_metadata, serialize_metadata


def test_metadata_roundtrip():
    meta = {"a": 1, "b": "two", "c": [1, 2, 3]}
    b = serialize_metadata(meta)
    assert isinstance(b, bytes)
    assert deserialize_metadata(b) == meta


def test_serialize_error(monkeypatch):
    import json

    def bad_dumps(*args, **kwargs):
        raise TypeError("boom")

    monkeypatch.setattr(json, "dumps", bad_dumps)
    with pytest.raises(MetadataError):
        serialize_metadata({"x": 42})


def test_deserialize_error():
    with pytest.raises(MetadataError):
        deserialize_metadata(b"not-a-json")
