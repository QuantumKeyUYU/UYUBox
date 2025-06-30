# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_kdf_dynamic.py

import os
import pytest

from zilant_prime_core.crypto.kdf import DEFAULT_KEY_LENGTH, derive_key, derive_key_dynamic, generate_salt
from zilant_prime_core.utils.constants import DEFAULT_SALT_LENGTH


def test_derive_key_basic_and_invalid():
    salt = generate_salt()
    # Успешная деривация
    key = derive_key("password", salt)
    assert isinstance(key, bytes) and len(key) == DEFAULT_KEY_LENGTH

    # Неверный тип пароля
    with pytest.raises(ValueError):
        derive_key(123, salt)  # password не str/bytes

    # Неверный тип соли
    with pytest.raises(ValueError):
        derive_key("password", "not-bytes")  # salt не bytes

    # Неверная длина ключа
    with pytest.raises(ValueError):
        derive_key("password", salt, key_length=0)


def test_derive_key_dynamic_basic_variation():
    salt = generate_salt()
    # Ключи для разных профилей должны отличаться
    k0 = derive_key_dynamic("password", salt, profile=0.0)
    k1 = derive_key_dynamic("password", salt, profile=1.5)
    assert isinstance(k0, bytes) and len(k0) == DEFAULT_KEY_LENGTH
    assert isinstance(k1, bytes) and len(k1) == DEFAULT_KEY_LENGTH
    assert k0 != k1


def test_derive_key_dynamic_extremes_do_not_fail():
    salt = generate_salt()
    # Профиль за границами → нормируется
    derive_key_dynamic("password", salt, profile=-100.0)
    derive_key_dynamic("password", salt, profile=100.0)


@pytest.mark.parametrize(
    "argname,kwargs",
    [
        (
            "password",
            dict(password=123, salt=os.urandom(DEFAULT_SALT_LENGTH), profile=0.5),
        ),
        ("salt", dict(password="password", salt=b"bad", profile=0.5)),
        (
            "profile",
            dict(password="password", salt=os.urandom(DEFAULT_SALT_LENGTH), profile="bad"),
        ),
        (
            "key_length",
            dict(
                password="password",
                salt=os.urandom(DEFAULT_SALT_LENGTH),
                profile=0.5,
                key_length=0,
            ),
        ),
        (
            "time_max",
            dict(
                password="password",
                salt=os.urandom(DEFAULT_SALT_LENGTH),
                profile=0.5,
                time_max=0,
            ),
        ),
        (
            "mem_min",
            dict(
                password="password",
                salt=os.urandom(DEFAULT_SALT_LENGTH),
                profile=0.5,
                mem_min=0,
            ),
        ),
        (
            "mem_max_lt_min",
            dict(
                password="password",
                salt=os.urandom(DEFAULT_SALT_LENGTH),
                profile=0.5,
                mem_min=4096,
                mem_max=1024,
            ),
        ),
    ],
)
def test_derive_key_dynamic_invalid_args(argname, kwargs):
    with pytest.raises(ValueError):
        derive_key_dynamic(**kwargs)
