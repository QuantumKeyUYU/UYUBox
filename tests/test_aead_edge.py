# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from types import ModuleType

from src.aead import PQAEAD, AEADInvalidTagError, decrypt_chacha20_poly1305


def test_decrypt_chacha20_poly1305_other_exception(monkeypatch):
    def bad_decrypt(self, *a, **k):
        raise RuntimeError("fail!")

    monkeypatch.setattr(ChaCha20Poly1305, "decrypt", bad_decrypt)
    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = b"x" * 32
    tag = b"x" * 16
    aad = b""
    with pytest.raises(AEADInvalidTagError) as excinfo:
        decrypt_chacha20_poly1305(key, nonce, ciphertext, tag, aad)
    assert "fail!" in str(excinfo.value)


def test_pqaead_encrypt_wrong_type(monkeypatch):
    pq_crypto = ModuleType("src.utils.pq_crypto")

    class DummyKyber768KEM:
        def encapsulate(self, pk):
            return (b"ct", b"shared")

    def derive_key_pq(shared):
        return b"x" * 32

    pq_crypto.Kyber768KEM = DummyKyber768KEM
    pq_crypto.derive_key_pq = derive_key_pq
    sys.modules["src.utils.pq_crypto"] = pq_crypto

    with pytest.raises(TypeError):
        PQAEAD.encrypt(123, b"x")
    with pytest.raises(TypeError):
        PQAEAD.encrypt(b"x", "notbytes")
    with pytest.raises(TypeError):
        PQAEAD.encrypt(b"x", b"x", aad="notbytes")


def test_pqaead_decrypt_wrong_type(monkeypatch):
    pq_crypto = ModuleType("src.utils.pq_crypto")

    class DummyKyber768KEM:
        def ciphertext_length(self):
            return 1

        def decapsulate(self, ct):
            return b"x" * 32

    def derive_key_pq(shared):
        return b"x" * 32

    pq_crypto.Kyber768KEM = DummyKyber768KEM
    pq_crypto.derive_key_pq = derive_key_pq
    sys.modules["src.utils.pq_crypto"] = pq_crypto

    with pytest.raises(TypeError):
        PQAEAD.decrypt(123, b"x")
    with pytest.raises(TypeError):
        PQAEAD.decrypt(b"x", "notbytes")
    with pytest.raises(TypeError):
        PQAEAD.decrypt(b"x", b"x", aad="notbytes")


def test_pqaead_decrypt_short_payload(monkeypatch):
    pq_crypto = ModuleType("src.utils.pq_crypto")

    class DummyKyber768KEM:
        def ciphertext_length(self):
            return 42

        def decapsulate(self, private_key, ct):  # <-- исправлено: принимает два аргумента
            return b"x" * 32

    def derive_key_pq(shared):
        return b"x" * 32

    pq_crypto.Kyber768KEM = DummyKyber768KEM
    pq_crypto.derive_key_pq = derive_key_pq
    sys.modules["src.utils.pq_crypto"] = pq_crypto

    with pytest.raises(ValueError):
        PQAEAD.decrypt(b"x" * 32, b"x")
