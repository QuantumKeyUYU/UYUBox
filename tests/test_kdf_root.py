# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from kdf import derive_key


def test_derive_key_valid():
    pwd = b"password"
    salt = b"saltysalt12345678"
    key = derive_key(pwd, salt)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_derive_key_password_type_error():
    with pytest.raises(TypeError):
        derive_key("password", b"salt")


def test_derive_key_salt_type_error():
    with pytest.raises(TypeError):
        derive_key(b"password", "salt")
