# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT


from zilant_prime_core.crypto.signature import KEY_SIZE, generate_keypair, sign, verify


def test_generate_keypair_returns_valid_keys():
    pub, priv = generate_keypair()
    # Оба ключа — байты нужной длины
    assert isinstance(pub, (bytes, bytearray))
    assert isinstance(priv, (bytes, bytearray))
    assert len(pub) == KEY_SIZE
    assert len(priv) == KEY_SIZE
    # В этой упрощённой схеме pub == priv
    assert pub == priv


def test_sign_and_verify_roundtrip():
    pub, priv = generate_keypair()
    msg = b"test-message"
    sig = sign(priv, msg)
    # Подпись должна быть правильной
    assert verify(pub, msg, sig) is True
    # Если изменить хотя бы один бит, verify даст False
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 1
    assert verify(pub, msg, bytes(bad_sig)) is False
