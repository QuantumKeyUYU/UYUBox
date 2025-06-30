# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

from zilant_prime_core.crypto.kdf import DEFAULT_SALT_LENGTH, derive_key_dynamic


def test_derive_key_dynamic_invalid_salt_type():
    # salt не байты → ValueError("Salt must be bytes.")
    with pytest.raises(ValueError) as exc:
        # передаём profile=0.5, а в salt строку
        derive_key_dynamic("password", "not-bytes", 0.5)
    assert "Salt must be bytes." in str(exc.value)


def test_derive_key_dynamic_invalid_salt_length():
    # salt байты, но неправильной длины → ValueError(f"Salt must be {DEFAULT_SALT_LENGTH} bytes long.")
    bad_salt = b"\x00" * (DEFAULT_SALT_LENGTH - 1)
    with pytest.raises(ValueError) as exc:
        # передаём profile=0.5
        derive_key_dynamic("password", bad_salt, 0.5)
    assert f"Salt must be {DEFAULT_SALT_LENGTH} bytes long." in str(exc.value)
