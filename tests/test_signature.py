# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

from zilant_prime_core.crypto.signature import SignatureError, generate_keypair, sign, verify


def test_signature_roundtrip():
    pub, priv = generate_keypair()
    msg = b"hello world"
    sig = sign(priv, msg)
    assert isinstance(sig, bytes)
    assert verify(pub, msg, sig)


def test_signature_tamper():
    pub, priv = generate_keypair()
    msg = b"hello"
    sig = sign(priv, msg)
    bad = sig[:-1] + bytes([sig[-1] ^ 0xFF])
    assert not verify(pub, msg, bad)


def test_sign_invalid_priv():
    with pytest.raises(SignatureError):
        sign(b"short", b"msg")


def test_verify_invalid_pub_or_sig():
    # короткий pub
    assert not verify(b"short", b"msg", b"sig")
    # короткая сигнатура
    pub, priv = generate_keypair()
    assert not verify(pub, b"msg", b"short")
