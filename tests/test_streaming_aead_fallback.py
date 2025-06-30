# tests/test_streaming_aead_fallback.py
import pytest
from typing import cast

# заставим ветку except в streaming_aead


# Подготовим фиктивные реализации PyNaCl
def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.startswith("cryptography.hazmat.primitives.ciphers.aead"):
        raise ImportError()
    return orig_import(name, globals, locals, fromlist, level)


orig_import = __import__
builtins_import = __builtins__["__import__"]
__builtins__["__import__"] = fake_import
import src.streaming_aead as saead  # force fallback branch

__builtins__["__import__"] = builtins_import

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt


@pytest.mark.parametrize("aad", [b"", b"hdr"])
def test_fallback_encrypt_decrypt(aad):
    key = b"\x00" * 32
    nonce = b"\x01" * 24
    data = b"DATA"
    # wrap C bindings для контроля
    # оригиналы вернут какой-то байт-стрим, проверим roundtrip
    ct = cast(bytes, crypto_aead_xchacha20poly1305_ietf_encrypt(data, aad, nonce, key))
    pt = cast(bytes, crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key))
    assert pt == data
    # и через наши функции
    ct2 = saead.encrypt_chunk(key, nonce, data, aad)
    pt2 = saead.decrypt_chunk(key, nonce, ct2, aad)
    assert pt2 == data
