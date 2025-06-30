# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from shard_secret import recover_secret, split_secret


def test_split_secret_invalid_parts():
    with pytest.raises(ValueError):
        split_secret(b"abc", parts=0)


def test_split_secret_single_part():
    secret = b"secret"
    assert split_secret(secret) == [secret]


def test_split_and_recover_multiple_parts():
    secret = b"bytes1234"
    shards = split_secret(secret, parts=3)
    assert len(shards) == 3
    assert recover_secret(shards) == secret


def test_recover_secret_empty():
    assert recover_secret([]) == b""
