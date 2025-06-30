# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

from zilant_prime_core.crypto.signature import KEY_SIZE, SIG_SIZE, SignatureError, sign, verify


def test_sign_invalid_priv_type():
    # priv не байты → SignatureError("Invalid private key.")
    with pytest.raises(SignatureError) as exc:
        sign("not-bytes", b"msg")
    assert "Invalid private key." in str(exc.value)


def test_sign_invalid_priv_length():
    # priv неправильной длины → SignatureError("Invalid private key.")
    with pytest.raises(SignatureError) as exc:
        sign(b"\x00" * (KEY_SIZE - 1), b"msg")
    assert "Invalid private key." in str(exc.value)


def test_sign_invalid_message_type():
    # priv корректного размера, но msg не bytes → SignatureError("Invalid message.")
    priv = b"\x00" * KEY_SIZE
    with pytest.raises(SignatureError) as exc:
        sign(priv, "not-bytes")
    assert "Invalid message." in str(exc.value)


def test_verify_invalid_pub_key_strict_true():
    # pub неправильной длины + strict=True → SignatureError("Invalid public key.")
    fake_sig = b"\x00" * SIG_SIZE
    with pytest.raises(SignatureError) as exc:
        verify(b"\x00" * (KEY_SIZE - 1), b"msg", fake_sig, strict=True)
    assert "Invalid public key." in str(exc.value)


def test_verify_invalid_msg_strict_true():
    # msg не байты + strict=True → SignatureError("Invalid message.")
    fake_pub = b"\x00" * KEY_SIZE
    fake_sig = b"\x00" * SIG_SIZE
    with pytest.raises(SignatureError) as exc:
        verify(fake_pub, "not-bytes", fake_sig, strict=True)
    assert "Invalid message." in str(exc.value)


def test_verify_invalid_sig_length_strict_true():
    # sig неправильной длины + strict=True → SignatureError("Invalid signature length.")
    fake_pub = b"\x00" * KEY_SIZE
    msg = b"msg"
    bad_sig = b"\x00" * (SIG_SIZE - 1)
    with pytest.raises(SignatureError) as exc:
        verify(fake_pub, msg, bad_sig, strict=True)
    assert "Invalid signature length." in str(exc.value)
