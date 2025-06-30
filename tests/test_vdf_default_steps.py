# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import hashlib
import pytest

from zilant_prime_core.vdf.vdf import generate_posw_sha256, verify_posw_sha256


def test_posw_default_steps_behavior():
    seed = b"default_seed"
    # без указания steps — равно вызову с steps=1
    p1 = generate_posw_sha256(seed)
    p2 = generate_posw_sha256(seed, 1)
    assert isinstance(p1, bytes) and isinstance(p2, bytes)
    assert p1 == p2
    # verify без указания тоже по steps=1
    assert verify_posw_sha256(seed, p1)
    assert verify_posw_sha256(seed, p2, 1)

    # и, конечно, неверный proof даёт False
    wrong = bytearray(p1)
    wrong[0] ^= 0xFF
    assert verify_posw_sha256(seed, bytes(wrong)) is False


def test_posw_default_steps_invalid():
    with pytest.raises(ValueError):
        generate_posw_sha256(b"ok", 0)
    with pytest.raises(ValueError):
        verify_posw_sha256(b"ok", hashlib.sha256(b"ok").digest(), 0)
    with pytest.raises(ValueError):
        generate_posw_sha256("no-bytes")  # type: ignore
    with pytest.raises(ValueError):
        verify_posw_sha256("no-bytes", b"", 1)  # type: ignore
