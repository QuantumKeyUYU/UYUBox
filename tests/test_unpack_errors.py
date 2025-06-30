# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_unpack_errors.py

import pytest
import struct

from zilant_prime_core.container.unpack import UnpackError, unpack
from zilant_prime_core.utils.constants import HEADER_FMT, MAGIC, VERSION


def _make_header(m=MAGIC, v=VERSION, meta=0, payload=0, tag=0):
    return struct.pack(HEADER_FMT, m, v, meta, payload, tag)


def test_unpack_too_short_header(tmp_path):
    # fewer than 4 bytes → UnpackError
    with pytest.raises(UnpackError):
        unpack(b"", tmp_path, password="pw")


def test_unpack_bad_magic(tmp_path):
    header = _make_header(m=b"BAD!", v=VERSION, meta=0, payload=0, tag=0)
    with pytest.raises(UnpackError):
        unpack(header + b"\x00" * 10, tmp_path, password="pw")


def test_unpack_bad_version(tmp_path):
    header = _make_header(m=MAGIC, v=99, meta=0, payload=0, tag=0)
    with pytest.raises(UnpackError):
        unpack(header + b"\x00" * 10, tmp_path, password="pw")
