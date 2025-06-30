# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import os
import pytest

from zilant_prime_core.crypto.aead import (
    DEFAULT_KEY_LENGTH,
    AEADInvalidTagError,
    decrypt_aead,
    encrypt_aead,
    generate_nonce,
)

KEY = os.urandom(DEFAULT_KEY_LENGTH)
NONCE = generate_nonce()
MSG = b"hi"


def test_bad_key_len():
    with pytest.raises(ValueError):
        encrypt_aead(KEY[:-1], NONCE, MSG)


def test_bad_nonce_len():
    with pytest.raises(ValueError):
        encrypt_aead(KEY, NONCE[:-1], MSG)


def test_invalid_tag():
    ct = encrypt_aead(KEY, NONCE, MSG)
    tampered = bytearray(ct)
    tampered[-1] ^= 1
    with pytest.raises(AEADInvalidTagError):
        decrypt_aead(KEY, NONCE, bytes(tampered))
