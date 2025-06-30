# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_signature_property.py

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zilant_prime_core.crypto.signature import SignatureError, generate_keypair, sign, verify


@given(msg=st.binary(min_size=0, max_size=1024))
def test_sign_verify_consistency(msg):
    pub, priv = generate_keypair()
    sig = sign(priv, msg)
    assert isinstance(sig, (bytes, bytearray))
    # Корректная верификация
    assert verify(pub, msg, sig)


def test_sign_invalid_key():
    # слишком короткий приватный ключ
    with pytest.raises(SignatureError):
        sign(b"short", b"msg")


@given(
    bad_pub=st.binary(min_size=0, max_size=31),
    msg=st.binary(),
    sig=st.binary(min_size=1, max_size=64),
)
def test_verify_invalid_inputs(bad_pub, msg, sig):
    # неверные публичный ключ, сообщение или сигнатура — всегда False
    assert verify(bad_pub, msg, sig) is False
