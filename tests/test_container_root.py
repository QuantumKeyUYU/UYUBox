# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import json
import pytest

import container
from container import HEADER_SEPARATOR, ZIL_MAGIC, ZIL_VERSION, pack_file, unpack_file
from crypto_core import hash_sha3


def test_pack_unpack_roundtrip_classic(tmp_path):
    inp = tmp_path / "in.txt"
    out = tmp_path / "out.zil"
    res = tmp_path / "res.txt"
    data = b"hello"
    inp.write_bytes(data)
    key = b"x" * 32
    pack_file(inp, out, key)
    assert out.exists()
    unpack_file(out, res, key)
    assert res.read_bytes() == data


def test_unpack_missing_separator(tmp_path):
    f = tmp_path / "f.zil"
    f.write_bytes(b"nosep")
    with pytest.raises(ValueError):
        unpack_file(f, tmp_path / "o", b"x" * 32)


def test_unpack_magic_mismatch(tmp_path):
    hdr = {
        "magic": "BAD",
        "version": ZIL_VERSION,
        "mode": "classic",
        "nonce_hex": "",
        "orig_size": 0,
        "checksum_hex": "",
    }
    data = json.dumps(hdr).encode() + HEADER_SEPARATOR + b""
    f = tmp_path / "f.zil"
    f.write_bytes(data)
    with pytest.raises(ValueError):
        unpack_file(f, tmp_path / "o", b"x" * 32)


def test_unpack_unsupported_version(tmp_path):
    hdr = {
        "magic": ZIL_MAGIC.decode(),
        "version": 999,
        "mode": "classic",
        "nonce_hex": "",
        "orig_size": 0,
        "checksum_hex": "",
    }
    data = json.dumps(hdr).encode() + HEADER_SEPARATOR + b""
    f = tmp_path / "f.zil"
    f.write_bytes(data)
    with pytest.raises(ValueError):
        unpack_file(f, tmp_path / "o", b"x" * 32)


def test_unpack_integrity_and_size(tmp_path, monkeypatch):
    # integrity failure
    plaintext = b"OK"
    nonce_hex = "00" * 12
    wrong_checksum = "deadbeef"
    hdr = {
        "magic": ZIL_MAGIC.decode(),
        "version": ZIL_VERSION,
        "mode": "classic",
        "nonce_hex": nonce_hex,
        "orig_size": len(plaintext),
        "checksum_hex": wrong_checksum,
    }
    f = tmp_path / "f.zil"
    f.write_bytes(json.dumps(hdr).encode() + HEADER_SEPARATOR + b"xxx")
    monkeypatch.setattr(container, "decrypt", lambda *a, **k: plaintext)
    with pytest.raises(ValueError):
        unpack_file(f, tmp_path / "o", b"x" * 32)
    # size mismatch
    correct_checksum = hash_sha3(plaintext).hex()
    hdr["checksum_hex"] = correct_checksum
    hdr["orig_size"] = len(plaintext) + 1
    f2 = tmp_path / "g.zil"
    f2.write_bytes(json.dumps(hdr).encode() + HEADER_SEPARATOR + b"xxx")
    monkeypatch.setattr(container, "decrypt", lambda *a, **k: plaintext)
    with pytest.raises(ValueError):
        unpack_file(f2, tmp_path / "o", b"x" * 32)
