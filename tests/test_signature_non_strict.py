# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT


from zilant_prime_core.crypto.signature import KEY_SIZE, SIG_SIZE, verify


def test_verify_invalid_public_key_non_strict():
    # неверный pub (короткий) + strict=False → False
    fake_sig = b"\x00" * SIG_SIZE
    result = verify(b"\x00" * (KEY_SIZE - 1), b"msg", fake_sig, strict=False)
    assert result is False


def test_verify_invalid_message_non_strict():
    # неверный msg (не байты) + strict=False → False
    fake_pub = b"\x00" * KEY_SIZE
    fake_sig = b"\x00" * SIG_SIZE
    result = verify(fake_pub, "not-bytes", fake_sig, strict=False)
    assert result is False


def test_verify_invalid_signature_length_non_strict():
    # неверный sig (короткий) + strict=False → False
    fake_pub = b"\x00" * KEY_SIZE
    msg = b"msg"
    bad_sig = b"\x00" * (SIG_SIZE - 1)
    result = verify(fake_pub, msg, bad_sig, strict=False)
    assert result is False
