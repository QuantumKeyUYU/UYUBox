# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_kdf.py

import builtins  # Add this import

from zilant_prime_core.crypto.kdf import DEFAULT_KEY_LENGTH, DEFAULT_SALT_LENGTH, derive_key, generate_salt


def debug_print(*args, **kwargs):
    """A simple print function that might work better in test environments."""
    builtins.print("DEBUG:", *args, **kwargs)


def test_derive_key():
    password = b"mysecretpassword"
    salt = generate_salt()
    key = derive_key(password, salt)
    assert isinstance(key, bytes)
    assert len(key) == DEFAULT_KEY_LENGTH

    # Deterministic for same inputs
    assert derive_key(password, salt) == key

    # Different password or salt → different key
    assert derive_key(b"wrong", salt) != key
    assert derive_key(password, generate_salt()) != key


def test_generate_salt():
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert isinstance(salt1, bytes)
    assert len(salt1) == DEFAULT_SALT_LENGTH
    assert salt1 != salt2  # Should be random
