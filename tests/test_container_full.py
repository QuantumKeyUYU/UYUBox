# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import json
import pytest
import secrets

from src import container


def test_pack_file_wrong_types(tmp_path):
    file_path = tmp_path / "f.txt"
    file_path.write_bytes(b"data")
    out_path = tmp_path / "out.zil"
    key = secrets.token_bytes(32)
    with pytest.raises(TypeError):
        container.pack_file("notpath", out_path, key)
    with pytest.raises(TypeError):
        container.pack_file(file_path, "notpath", key)
    with pytest.raises(TypeError):
        container.pack_file(file_path, out_path, "notbytes")
    with pytest.raises(ValueError):
        container.pack_file(file_path, out_path, b"x" * 16)


def test_unpack_file_wrong_types(tmp_path):
    file_path = tmp_path / "f.txt"
    file_path.write_bytes(b"data")
    out_path = tmp_path / "out.zil"
    key = secrets.token_bytes(32)
    container.pack_file(file_path, out_path, key)
    with pytest.raises(TypeError):
        container.unpack_file("notpath", tmp_path / "o", key)
    with pytest.raises(TypeError):
        container.unpack_file(out_path, "notpath", key)
    with pytest.raises(TypeError):
        container.unpack_file(out_path, tmp_path / "o", "notbytes")
    with pytest.raises(ValueError):
        container.unpack_file(out_path, tmp_path / "o", b"x" * 8)


def test_pack_unpack_pq_path(tmp_path, monkeypatch):
    # Мокаем PQAEAD и Kyber768KEM — без настоящих pq-ключей
    class DummyPQ:
        _NONCE_LEN = 12

        @staticmethod
        def encrypt(pk, pt, aad=b""):
            return b"pqct" + b"NONCE123456" + b"PQENCRYPTED"

    monkeypatch.setattr(container, "PQAEAD", DummyPQ)
    file_path = tmp_path / "f.txt"
    file_path.write_bytes(b"data")
    out_path = tmp_path / "pq.zil"
    key = secrets.token_bytes(32)
    container.pack_file(file_path, out_path, key, pq_public_key=b"pqpubkey")
    assert out_path.exists()


def test_unpack_wrong_header(tmp_path):
    p = tmp_path / "c.zil"
    p.write_bytes(b"badheader\n\nbadpayload")
    with pytest.raises(json.JSONDecodeError):
        container.unpack_file(p, tmp_path / "o", b"x" * 32)


def test_pack_meta_payload_key_types():
    meta = {"foo": "bar"}
    payload = b"hi"
    key = secrets.token_bytes(32)
    assert isinstance(container.pack(meta, payload, key), bytes)
    with pytest.raises(TypeError):
        container.pack("notadict", payload, key)
    with pytest.raises(TypeError):
        container.pack(meta, "notbytes", key)
    with pytest.raises(TypeError):
        container.pack(meta, payload, "notbytes")
    with pytest.raises(ValueError):
        container.pack(meta, payload, b"x" * 16)


def test_unpack_blob_key_types():
    meta = {"foo": "bar"}
    payload = b"hi"
    key = secrets.token_bytes(32)
    blob = container.pack(meta, payload, key)
    assert container.unpack(blob, key)[1] == payload
    with pytest.raises(TypeError):
        container.unpack(123, key)
    with pytest.raises(TypeError):
        container.unpack(blob, "notbytes")
    with pytest.raises(ValueError):
        container.unpack(blob, b"x" * 4)
