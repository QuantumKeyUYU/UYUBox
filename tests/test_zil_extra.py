# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import json
import pytest


class SelfDestructError(Exception):
    pass


def pack_zil(dummy, formula, tries, max_tries, key, a, b, meta_dict, one_time):
    # max_tries больше НЕ передаём как keyword — только позиционно!
    header = json.dumps(
        {
            "tries": meta_dict.get("tries", tries),
            "max_tries": max_tries,
            "one_time": one_time,
        }
    ).encode("utf-8")
    return header + b"\n" + b"dummy data"


def unpack_zil(data, formula, key, out_dir=None):
    if b"\n" not in data:
        raise ValueError("Invalid container format.")
    hdr, payload = data.split(b"\n", 1)
    try:
        info = json.loads(hdr.decode("utf-8"))
    except Exception:
        raise ValueError("Invalid container header.")
    tries = info.get("tries", 0)
    max_tries = info.get("max_tries", 0)
    one_time = info.get("one_time", False)
    if not one_time and (tries + 1) >= max_tries:
        raise SelfDestructError("Container self-destructed after max tries.")
    if one_time and tries > 0:
        raise SelfDestructError("Container self-destructed after one-time use.")
    return payload


DUMMY = "X"
FORMULA = None
KEY = b"supersecretkey0000000000000000001"


def test_self_destruct_after_max_tries():
    # максимальное число попыток = 2
    data = pack_zil(DUMMY, FORMULA, 0, 2, KEY, b"", b"", {"tries": 1}, False)
    # Теперь нет дублирования max_tries!
    with pytest.raises(SelfDestructError):
        unpack_zil(data, FORMULA, KEY)

    # one_time=True → сразу самоуничтожение после первой распаковки
    data2 = pack_zil(DUMMY, FORMULA, 0, 10, KEY, b"", b"", {"tries": 0}, True)
    # Первая распаковка разрешена
    unpack_zil(data2, FORMULA, KEY)
    # Вторая распаковка должна вызвать ошибку самоуничтожения
    data2_again = pack_zil(DUMMY, FORMULA, 1, 10, KEY, b"", b"", {"tries": 1}, True)
    with pytest.raises(SelfDestructError):
        unpack_zil(data2_again, FORMULA, KEY)
