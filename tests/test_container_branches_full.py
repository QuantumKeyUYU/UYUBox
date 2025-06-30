# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
import secrets

from src.container import pack, pack_file, unpack, unpack_file


def test_pack_invalid_meta():
    payload = b"payload"
    key = secrets.token_bytes(32)
    with pytest.raises(TypeError):
        pack("notadict", payload, key)


def test_pack_invalid_key():
    meta = {"foo": "bar"}
    payload = b"payload"
    with pytest.raises(ValueError):
        pack(meta, payload, b"shortkey")


def test_unpack_invalid_key():
    meta = {"foo": "bar"}
    payload = b"payload"
    key = secrets.token_bytes(32)
    blob = pack(meta, payload, key)
    with pytest.raises(ValueError):
        unpack(blob, b"shortkey")


def test_unpack_invalid_blob_type():
    key = secrets.token_bytes(32)
    with pytest.raises(TypeError):
        unpack(1234, key)


def test_pack_file_invalid_path(tmp_path):
    with pytest.raises(TypeError):
        pack_file(123, tmp_path / "out", b"x" * 32)


def test_unpack_file_invalid_path(tmp_path):
    with pytest.raises(TypeError):
        unpack_file(123, tmp_path / "out", b"x" * 32)


def test_pack_file_invalid_password(tmp_path):
    f = tmp_path / "f.txt"
    f.write_bytes(b"x")
    with pytest.raises(TypeError):
        pack_file(f, tmp_path / "out", "notbytes")


def test_unpack_file_invalid_password(tmp_path):
    f = tmp_path / "f.txt"
    f.write_bytes(b"x")
    key = b"x" * 32
    pack_file(f, tmp_path / "out.zil", key)
    with pytest.raises(TypeError):
        unpack_file(tmp_path / "out.zil", tmp_path / "out2", "notbytes")
