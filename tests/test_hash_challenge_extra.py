# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from zilant_prime_core.utils import hash_challenge as hc


def test_hash_challenge_caches_result(tmp_path):
    f = tmp_path / "test.txt"
    f.write_bytes(b"data")
    result1 = hc.hash_challenge(str(f))
    result2 = hc.hash_challenge(str(f))
    assert result1 == result2


def test_hash_challenge_missing_file(tmp_path):
    missing = tmp_path / "missing.txt"
    value = hc.hash_challenge(str(missing))
    assert isinstance(value, str)
    assert len(value) == 64
