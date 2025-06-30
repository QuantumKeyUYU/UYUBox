# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from utils.secure_memory import wipe_bytes


def test_wipe_bytes_valid():
    buf = bytearray(b"hello")
    wipe_bytes(buf)
    assert all(b == 0 for b in buf)


def test_wipe_bytes_invalid_type():
    with pytest.raises(TypeError):
        wipe_bytes(b"bytes")
