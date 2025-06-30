# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_zil_root.py

import json
import pytest

from zil import SelfDestructError, pack_zil, unpack_zil


def make_container(info, payload=b"OK"):
    hdr = json.dumps(info, separators=(",", ":")).encode()
    return hdr + b"\n" + payload


def test_pack_rejects_non_bytes_payload():
    with pytest.raises(ValueError):
        pack_zil(
            "not-bytes",
            formula=None,
            lam=0.1,
            steps=1,
            key=b"k",
            salt=b"s",
            nonce=b"n",
            metadata={},
            max_tries=3,
            one_time=False,
        )


def test_unpack_rejects_missing_newline():
    with pytest.raises(ValueError, match="Invalid container format"):
        unpack_zil(b"no-newline-here", formula=None, key=b"k", out_dir=None)


def test_unpack_rejects_bad_json_header():
    bad = b"not-json\nPAY"
    with pytest.raises(ValueError, match="Invalid container header"):
        unpack_zil(bad, formula=None, key=b"k", out_dir=None)


def test_unpack_self_destruct_after_max_tries():
    cont = make_container({"tries": 2, "max_tries": 3, "one_time": False}, b"X")
    with pytest.raises(SelfDestructError):
        unpack_zil(cont, formula=None, key=b"k", out_dir=None)


def test_unpack_allows_if_under_max():
    cont = make_container({"tries": 1, "max_tries": 3, "one_time": False}, b"DATA")
    assert unpack_zil(cont, formula=None, key=b"k", out_dir=None) == b"DATA"


def test_unpack_one_time_ignores_tries():
    # В корневом zil.py ветка one_time не поддерживает самоуничтожение — всегда отдаёт payload
    cont = make_container({"tries": 5, "max_tries": 3, "one_time": True}, b"DATA")
    assert unpack_zil(cont, formula=None, key=b"k", out_dir=None) == b"DATA"
