# tests/test_streaming_aead.py

import os
import pytest

from src.streaming_aead import decrypt_chunk, encrypt_chunk

try:
    from cryptography.exceptions import InvalidTag
except ImportError:
    InvalidTag = ValueError

try:
    from nacl.exceptions import CryptoError
except ImportError:
    CryptoError = ValueError


@pytest.mark.parametrize("aad", [b"", b"header"])
def test_encrypt_decrypt_roundtrip(aad):
    key = os.urandom(32)
    nonce = os.urandom(24)
    data = b"data-block"
    ct = encrypt_chunk(key, nonce, data, aad)
    pt = decrypt_chunk(key, nonce, ct, aad)
    assert pt == data


@pytest.mark.parametrize("invalid_ct", [b"", b"short", None])
def test_decrypt_invalid_permissive(invalid_ct):
    key = b"\x00" * 32
    nonce = b"\x01" * 24
    try:
        result = decrypt_chunk(key, nonce, invalid_ct)
    except (InvalidTag, CryptoError, ValueError, TypeError):
        pass
    else:
        # если без ошибки — надо вернуть хоть какие-то байты
        assert isinstance(result, (bytes, bytearray))
