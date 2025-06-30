# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from zilant_prime_core.utils.shard_secret import recover_secret, split_secret


def test_shard_split_and_recover():
    data = b"secret"
    shards = split_secret(data)
    assert shards and recover_secret(shards) == data
