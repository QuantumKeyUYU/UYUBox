# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import importlib

# tests/test_pack_unpack_errors.py
import json
import pytest
from pathlib import Path

from zilant_prime_core.container.pack import pack
from zilant_prime_core.container.unpack import UnpackError, unpack
from zilant_prime_core.crypto.aead import AEADInvalidTagError
from zilant_prime_core.utils.constants import DEFAULT_NONCE_LENGTH, DEFAULT_SALT_LENGTH

# Настоящий объект-модуль, а не функция
unpack_module = importlib.import_module("zilant_prime_core.container.unpack")


def test_unpack_too_short_for_meta():
    with pytest.raises(UnpackError, match="слишком мал"):
        unpack(b"", "/tmp", "pw")


def test_unpack_incomplete_meta():
    bad = (10).to_bytes(4, "big")
    with pytest.raises(UnpackError, match="Неполные метаданные"):
        unpack(bad, "/tmp", "pw")


def test_unpack_bad_json_in_meta():
    blob = b"not-json"
    raw = len(blob).to_bytes(4, "big") + blob
    with pytest.raises(UnpackError, match="Не удалось разобрать метаданные"):
        unpack(raw, "/tmp", "pw")


def test_unpack_missing_salt():
    meta = json.dumps({"filename": "a", "size": 0}).encode()
    raw = len(meta).to_bytes(4, "big") + meta
    with pytest.raises(UnpackError, match="salt"):
        unpack(raw, "/tmp", "pw")


def test_unpack_missing_nonce():
    meta = json.dumps({"filename": "a", "size": 0}).encode()
    blob = len(meta).to_bytes(4, "big") + meta + b"\x00" * DEFAULT_SALT_LENGTH
    with pytest.raises(UnpackError, match="nonce"):
        unpack(blob, "/tmp", "pw")


def test_unpack_short_ciphertext():
    meta = json.dumps({"filename": "a", "size": 0}).encode()
    blob = (
        len(meta).to_bytes(4, "big")
        + meta
        + b"\x00" * DEFAULT_SALT_LENGTH
        + b"\x00" * DEFAULT_NONCE_LENGTH
        + b"\x01" * 8
    )
    with pytest.raises(UnpackError, match="Ciphertext слишком короткий"):
        unpack(blob, "/tmp", "pw")


def test_unpack_invalid_tag(monkeypatch):
    # Подменяем ТОЛЬКО decrypt_aead внутри модуля unpack
    def bad_decrypt(*_args, **_kwargs):
        raise AEADInvalidTagError

    monkeypatch.setattr(unpack_module, "decrypt_aead", bad_decrypt)

    meta = json.dumps({"filename": "a", "size": 0}).encode()
    salt = b"\x00" * DEFAULT_SALT_LENGTH
    nonce = b"\x00" * DEFAULT_NONCE_LENGTH
    ct = b"\x00" * 16  # «валидная» длина, чтобы пройти проверку
    raw = len(meta).to_bytes(4, "big") + meta + salt + nonce + ct

    with pytest.raises(UnpackError, match="Неверная метка"):
        unpack(raw, "/tmp", "pw")


def test_pack_and_unpack_roundtrip(tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"DATA")
    cont = pack(src, "pass")
    out = unpack(cont, tmp_path / "out", "pass")
    assert Path(out).read_bytes() == b"DATA"
