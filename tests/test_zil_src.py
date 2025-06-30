# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_zil_src.py

import json
import pytest
import struct

from src.zil import SelfDestructError, pack_zill
from src.zil import unpack_zil as unpack_src


def test_pack_zill_embeds_meta_and_payload():
    payload = b"HELLO"
    data = pack_zill(
        payload,
        formula=None,
        lam=None,
        steps=None,
        key=None,
        salt=None,
        nonce=None,
        metadata={"foo": 1},
        max_tries=5,
        one_time=True,
    )
    meta_len = struct.unpack(">I", data[:4])[0]
    meta_bytes = data[4 : 4 + meta_len]
    meta = json.loads(meta_bytes.decode("utf-8"))
    assert meta["foo"] == 1
    assert meta["max_tries"] == 5
    assert meta["one_time"] is True
    assert data[4 + meta_len :] == payload


def test_unpack_src_one_time_fails_on_second_try():
    meta = {"tries": 1, "max_tries": 2, "one_time": True}
    mb = json.dumps(meta).encode("utf-8")
    data = struct.pack(">I", len(mb)) + mb + b"PAY"
    with pytest.raises(SelfDestructError):
        unpack_src(data, formula=None, key=None, out_dir="")


def test_unpack_src_max_tries_exceeded():
    meta = {"tries": 1, "max_tries": 2, "one_time": False}
    mb = json.dumps(meta).encode("utf-8")
    data = struct.pack(">I", len(mb)) + mb + b"EOF"
    with pytest.raises(SelfDestructError):
        unpack_src(data, formula=None, key=None, out_dir="")


def test_unpack_src_allows_if_under_max():
    payload = b"PAY"
    meta = {"tries": 1, "max_tries": 3, "one_time": False}
    mb = json.dumps(meta).encode("utf-8")
    data = struct.pack(">I", len(mb)) + mb + payload
    assert unpack_src(data, formula=None, key=None, out_dir="") == payload
