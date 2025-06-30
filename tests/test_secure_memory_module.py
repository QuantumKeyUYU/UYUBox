# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

import pytest

from utils.secure_memory import wipe_bytes


def test_wipe_bytes_type_error():
    with pytest.raises(TypeError):
        wipe_bytes(b"abc")


def test_wipe_bytes_zeroes():
    buf = bytearray(b"secret")
    wipe_bytes(buf)
    assert buf == b"\x00" * 6
