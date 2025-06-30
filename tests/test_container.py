# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

import container


@pytest.fixture
def tmp_file(tmp_path):
    p = tmp_path / "f.zil"
    p.write_bytes(b"no_header")
    return p


def test_pack_file_type_checks(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"12" * 16)
    out = tmp_path / "out.zil"
    # неправильные типы input_path/output_path/key
    with pytest.raises(TypeError):
        container.pack_file(str(f), out, b"x" * 32)  # type: ignore
    with pytest.raises(TypeError):
        container.pack_file(f, str(out), b"x" * 32)  # type: ignore
    with pytest.raises(TypeError):
        container.pack_file(f, out, "no_bytes")  # type: ignore
    # короткий ключ
    with pytest.raises(ValueError):
        container.pack_file(f, out, b"shortkey")


def test_unpack_file_type_checks(tmp_path):
    f = tmp_path / "f"
    out = tmp_path / "out"
    f.write_bytes(b"")
    # неправильные типы
    with pytest.raises(TypeError):
        container.unpack_file(str(f), out, b"x" * 32)  # type: ignore
    with pytest.raises(TypeError):
        container.unpack_file(f, str(out), b"x" * 32)  # type: ignore
    with pytest.raises(TypeError):
        container.unpack_file(f, out, "no_bytes")  # type: ignore
    # короткий ключ
    with pytest.raises(ValueError):
        container.unpack_file(f, out, b"shortkey")


def test_pack_unpack_blob_errors():
    # pack(meta, payload, key)
    with pytest.raises(TypeError):
        container.pack("not_dict", b"payload", b"x" * 32)  # type: ignore
    with pytest.raises(TypeError):
        container.pack({}, "not_bytes", b"x" * 32)  # type: ignore
    with pytest.raises(TypeError):
        container.pack({}, b"x", "not_bytes")  # type: ignore
    with pytest.raises(ValueError):
        container.pack({}, b"x", b"x")  # ключ неправильной длины

    # unpack(blob, key)
    with pytest.raises(TypeError):
        container.unpack("not_bytes", b"x" * 32)  # type: ignore
    with pytest.raises(TypeError):
        container.unpack(b"x", "not_bytes")  # type: ignore
    with pytest.raises(ValueError):
        container.unpack(b"x", b"x" * 32)  # HEADER_SEPARATOR не найден


def test_get_metadata_invalid(tmp_path):
    p = tmp_path / "broken.zil"
    p.write_bytes(b"badheader")
    with pytest.raises(ValueError):
        container.get_metadata(p)


def test_verify_integrity_variants(tmp_path):
    # bad header → False
    p1 = tmp_path / "broken.zil"
    p1.write_bytes(b"badheader")
    assert not container.verify_integrity(p1)

    # bad JSON → False
    p2 = tmp_path / "badjson.zil"
    p2.write_bytes(b"{badjson}\n\n123")
    assert not container.verify_integrity(p2)

    # wrong magic → False
    import json

    m1 = {"magic": "XXX", "version": 1, "orig_size": 0}
    data1 = json.dumps(m1).encode() + b"\n\n"
    p3 = tmp_path / "m1.zil"
    p3.write_bytes(data1)
    assert not container.verify_integrity(p3)

    # wrong version → False
    m2 = {"magic": "ZILANT", "version": 999, "orig_size": 0}
    data2 = json.dumps(m2).encode() + b"\n\n"
    p4 = tmp_path / "m2.zil"
    p4.write_bytes(data2)
    assert not container.verify_integrity(p4)
