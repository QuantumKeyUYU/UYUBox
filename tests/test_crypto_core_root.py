# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import hashlib
import pytest

from crypto_core import hash_sha3


def test_hash_sha3_bytes():
    data = b"abc"
    digest = hash_sha3(data)
    assert isinstance(digest, bytes)
    assert len(digest) == hashlib.sha3_256().digest_size


def test_hash_sha3_string():
    assert hash_sha3("abc") == hash_sha3(b"abc")


def test_hash_sha3_path(tmp_path):
    p = tmp_path / "f.txt"
    content = b"data"
    p.write_bytes(content)
    assert hash_sha3(p) == hash_sha3(content)


def test_hash_sha3_hex_output():
    hex_digest = hash_sha3(b"abc", hex_output=True)
    assert isinstance(hex_digest, str)
    assert len(hex_digest) == hashlib.sha3_256().digest_size * 2


def test_hash_sha3_invalid_type():
    with pytest.raises(TypeError):
        hash_sha3(123)
