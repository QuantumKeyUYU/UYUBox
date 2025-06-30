# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
import secrets

from src import container


def test_pack_file_key_length(tmp_path):
    file_path = tmp_path / "f.txt"
    file_path.write_bytes(b"data")
    out_path = tmp_path / "out.zil"
    # key длиной не 32
    with pytest.raises(ValueError):
        container.pack_file(file_path, out_path, b"x" * 31)


def test_unpack_file_integrity_check(tmp_path):
    file_path = tmp_path / "f.txt"
    file_path.write_bytes(b"12345678")
    out_path = tmp_path / "out.zil"
    key = secrets.token_bytes(32)
    container.pack_file(file_path, out_path, key)
    # Мутим контрольную сумму
    data = out_path.read_bytes()
    idx = data.find(b"\n\n")
    import json

    meta = json.loads(data[:idx].decode())
    meta["checksum_hex"] = "0" * 64
    corrupt = json.dumps(meta).encode() + b"\n\n" + data[idx + 2 :]
    out_path.write_bytes(corrupt)
    with pytest.raises(ValueError):
        container.unpack_file(out_path, tmp_path / "out2", key)


def test_unpack_file_size_check(tmp_path):
    file_path = tmp_path / "f.txt"
    file_path.write_bytes(b"12345678")
    out_path = tmp_path / "out.zil"
    key = secrets.token_bytes(32)
    container.pack_file(file_path, out_path, key)
    data = out_path.read_bytes()
    idx = data.find(b"\n\n")
    import json

    meta = json.loads(data[:idx].decode())
    meta["orig_size"] = 77
    corrupt = json.dumps(meta).encode() + b"\n\n" + data[idx + 2 :]
    out_path.write_bytes(corrupt)
    with pytest.raises(ValueError):
        container.unpack_file(out_path, tmp_path / "out2", key)


def test_pack_wrong_types():
    with pytest.raises(TypeError):
        container.pack(123, b"x", b"x" * 32)
    with pytest.raises(TypeError):
        container.pack({"foo": "bar"}, "notbytes", b"x" * 32)
    with pytest.raises(TypeError):
        container.pack({"foo": "bar"}, b"x", "notbytes")
