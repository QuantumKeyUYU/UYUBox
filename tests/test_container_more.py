# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

import src.container as container


def test_pack_and_unpack_file_classic(tmp_path):
    src_file = tmp_path / "in.bin"
    data = b"CLASSIC"
    src_file.write_bytes(data)
    out = tmp_path / "out.zil"
    dest = tmp_path / "dest.bin"
    key = b"x" * 32
    container.pack_file(src_file, out, key)
    container.unpack_file(out, dest, key)
    assert dest.read_bytes() == data


def test_pack_file_pq_public_key_type(tmp_path):
    f = tmp_path / "file.bin"
    f.write_bytes(b"DATA")
    with pytest.raises(TypeError):
        container.pack_file(f, tmp_path / "o.zil", b"x" * 32, pq_public_key="notbytes")


def test_pack_file_pq_mode_success(tmp_path, monkeypatch):
    f = tmp_path / "file2.bin"
    content = b"PQMODE"
    f.write_bytes(content)
    out = tmp_path / "out2.zil"
    key = b"x" * 32

    # stub PQAEAD.encrypt so it accepts the 'aad' keyword
    def fake_encrypt(pk, pt, aad=b""):
        return b"KEM" + pt

    monkeypatch.setattr(container.PQAEAD, "encrypt", staticmethod(fake_encrypt))

    container.pack_file(f, out, key, pq_public_key=b"pub")
    raw = out.read_bytes()
    idx = raw.find(b"\n\n")
    payload = raw[idx + 2 :]
    assert payload.startswith(b"KEM" + content)


def test_unpack_file_pq_private_key_type(tmp_path, monkeypatch):
    f = tmp_path / "f3.bin"
    f.write_bytes(b"HELLO")
    out = tmp_path / "out3.zil"
    key = b"x" * 32

    # stub PQAEAD.encrypt
    def fake_encrypt(pk, pt, aad=b""):
        return b"KEMCT" + pt

    monkeypatch.setattr(container.PQAEAD, "encrypt", staticmethod(fake_encrypt))

    container.pack_file(f, out, key, pq_public_key=b"pub")
    with pytest.raises(TypeError):
        container.unpack_file(out, tmp_path / "dest3", key, pq_private_key="notbytes")
