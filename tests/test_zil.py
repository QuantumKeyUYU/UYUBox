# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_zil.py

import pytest

from landscape import generate_sat
from zil import SelfDestructError, pack_zil, unpack_zil

# Параметры для тестирования
FORMULA = generate_sat(5, 2.0)
LAMBDA = 0.1
STEPS = 3
KEY = b"0" * 32
SALT = b"1" * 16
NONCE = b"2" * 12


def test_pack_unpack_roundtrip(tmp_path):
    payload = b"hello world"
    meta = {"info": "test", "tries": 0}

    data = pack_zil(
        payload=payload,
        formula=FORMULA,
        lam=LAMBDA,
        steps=STEPS,
        key=KEY,
        salt=SALT,
        nonce=NONCE,
        metadata=meta.copy(),
        max_tries=3,
        one_time=True,
    )

    # Проверяем, что модуль может распаковать ровно один раз
    result = unpack_zil(data=data, formula=FORMULA, key=KEY, out_dir=str(tmp_path))
    assert result == payload


def test_self_destruct_after_three_failures(tmp_path):
    payload = b"secret data"
    # Симулируем уже 2 неудачные попытки:
    meta = {"tries": 2}

    data = pack_zil(
        payload=payload,
        formula=FORMULA,
        lam=LAMBDA,
        steps=STEPS,
        key=KEY,
        salt=SALT,
        nonce=NONCE,
        metadata=meta,
        max_tries=3,
        one_time=False,
    )

    # Третья попытка должна выбросить SelfDestructError
    with pytest.raises(SelfDestructError):
        unpack_zil(data=data, formula=FORMULA, key=KEY, out_dir=str(tmp_path))
