# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
import json
import pytest
import secrets

from zilant_prime_core import uniform_container as container


def test_uniform_pack_unpack():
    meta = {"foo": "bar"}
    payload = secrets.token_bytes(100)
    key = secrets.token_bytes(32)
    blob = container.pack(meta, payload, key)
    assert (len(blob) - 12 - 16) % 4096 == 0
    m2, p2 = container.unpack(blob, key)
    assert m2 == meta
    assert p2 == payload


def test_unpack_missing_length(monkeypatch):
    meta = {"foo": "bar"}
    payload = b"hi"
    key = secrets.token_bytes(32)
    blob = container.pack(meta, payload, key)
    original = container.decrypt_chacha20_poly1305

    def fake_decrypt(key2, nonce, ct):
        plain = original(key2, nonce, ct)
        meta_len = int.from_bytes(plain[:4], "big")
        meta_json = plain[4 : 4 + meta_len]
        m = json.loads(meta_json.decode())
        m.pop("_payload_length")
        new_meta = json.dumps(m).encode()
        return len(new_meta).to_bytes(4, "big") + new_meta + plain[4 + meta_len :]

    monkeypatch.setattr(container, "decrypt_chacha20_poly1305", fake_decrypt)
    with pytest.raises(ValueError):
        container.unpack(blob, key)
