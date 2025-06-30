# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from container import pack_file, unpack_file


@settings(suppress_health_check=(HealthCheck.function_scoped_fixture,))
@given(data=st.binary(min_size=0, max_size=2048))
def test_pack_unpack_roundtrip(tmp_path, data):
    src = tmp_path / "inp.bin"
    src.write_bytes(data)
    cont = tmp_path / "c.zil"
    pack_file(src, cont, b"k" * 32)
    out = tmp_path / "out.bin"
    unpack_file(cont, out, b"k" * 32)
    assert out.read_bytes() == data
