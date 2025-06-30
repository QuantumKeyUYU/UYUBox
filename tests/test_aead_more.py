# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
import sys
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from types import ModuleType

from src.aead import PQAEAD, AEADInvalidTagError, decrypt_chacha20_poly1305


def test_decrypt_chacha20_poly1305_invalid_tag(monkeypatch):
    # InvalidTag branch
    def raise_it(self, nonce, data, aad):
        raise InvalidTag()

    monkeypatch.setattr(ChaCha20Poly1305, "decrypt", raise_it)
    with pytest.raises(AEADInvalidTagError) as exc:
        decrypt_chacha20_poly1305(b"\x00" * 32, b"\x00" * 12, b"x" * 16, b"\x00" * 16)
    assert "Invalid authentication tag." in str(exc.value)


def test_decrypt_chacha20_poly1305_aad_type_error():
    with pytest.raises(TypeError):
        decrypt_chacha20_poly1305(b"\x00" * 32, b"\x00" * 12, b"x" * 16, b"\x00" * 16, aad="notbytes")


def test_pqaead_encrypt_decrypt_roundtrip(monkeypatch):
    # stub src.utils.pq_crypto
    pq = ModuleType("src.utils.pq_crypto")

    class DummyKEM:
        def encapsulate(self, pk):
            return (b"KEMCT", b"SHARED")

        def ciphertext_length(self):
            return len(b"KEMCT")

        def decapsulate(self, priv, kem_ct):
            assert kem_ct == b"KEMCT"
            return b"SHARED"

    pq.Kyber768KEM = DummyKEM
    pq.derive_key_pq = lambda shared: b"\x01" * 32
    sys.modules["src.utils.pq_crypto"] = pq

    # patch ChaCha20Poly1305 to a dummy that simply returns plaintext
    import src.aead as aead_mod

    class DummyChaCha:
        def __init__(self, key):
            pass

        def encrypt(self, nonce, pt, aad):
            return pt + aad

        def decrypt(self, nonce, ct, aad):
            return ct[: -len(aad)] if aad else ct

    aead_mod.ChaCha20Poly1305 = DummyChaCha

    msg = b"hello!"
    aad = b"AA"
    payload = PQAEAD.encrypt(b"pubkey", msg, aad=aad)
    result = PQAEAD.decrypt(b"privkey", payload, aad=aad)
    assert result == msg


@pytest.mark.parametrize("bad", [123, None, b"short"])
def test_pqaead_encrypt_type_errors(bad, monkeypatch):
    pq = ModuleType("src.utils.pq_crypto")
    pq.Kyber768KEM = type("KEM", (), {"encapsulate": staticmethod(lambda pk: (b"", b""))})()
    pq.derive_key_pq = lambda shared: b"\x00" * 32
    sys.modules["src.utils.pq_crypto"] = pq
    with pytest.raises(TypeError):
        PQAEAD.encrypt(bad, b"x", b"")
    with pytest.raises(TypeError):
        PQAEAD.encrypt(b"x", bad, b"")
    with pytest.raises(TypeError):
        PQAEAD.encrypt(b"x", b"x", bad)


@pytest.mark.parametrize("bad", [123, None, b"short"])
def test_pqaead_decrypt_type_errors(bad, monkeypatch):
    pq = ModuleType("src.utils.pq_crypto")
    pq.Kyber768KEM = type("KEM", (), {"ciphertext_length": lambda self: 1, "decapsulate": lambda self, pk, ct: b""})()
    pq.derive_key_pq = lambda shared: b"\x00" * 32
    sys.modules["src.utils.pq_crypto"] = pq
    with pytest.raises(TypeError):
        PQAEAD.decrypt(bad, b"x", b"")
    with pytest.raises(TypeError):
        PQAEAD.decrypt(b"x", bad, b"")
    with pytest.raises(TypeError):
        PQAEAD.decrypt(b"x", b"x", bad)
