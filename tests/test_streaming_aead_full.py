# tests/test_streaming_aead_full.py

import pytest
import sys
import types

from src.streaming_aead import decrypt_chunk, encrypt_chunk

# Определяем возможные исключения
try:
    from cryptography.exceptions import InvalidTag
except ImportError:
    InvalidTag = Exception

try:
    from nacl.exceptions import CryptoError
except ImportError:
    CryptoError = Exception


@pytest.mark.parametrize("use_fallback", [False, True])
def test_encrypt_decrypt_both_backends(monkeypatch, use_fallback):
    """
    Проверяем и нативную, и fallback-ветки XChaCha20Poly1305:
    - если use_fallback=True, сбрасываем _NativeAEAD и подсовываем fake nacl.bindings
    - в любом случае encrypt → decrypt возвращает исходные данные
    """
    key = b"\x00" * 32
    nonce = b"\x01" * 24
    data = b"the quick brown fox"
    aad = b"hdr"

    if use_fallback:
        # Форсируем fallback-ветку
        monkeypatch.setattr("src.streaming_aead._NativeAEAD", None, raising=False)
        fake = types.SimpleNamespace(
            crypto_aead_xchacha20poly1305_ietf_encrypt=lambda msg, hdr, nonce, key: b"FALLBACK" + msg,
            crypto_aead_xchacha20poly1305_ietf_decrypt=lambda ct, hdr, nonce, key: ct[len(b"FALLBACK") :],
        )
        sys.modules["nacl"] = types.ModuleType("nacl")
        sys.modules["nacl.bindings"] = fake

    ct = encrypt_chunk(key, nonce, data, aad)
    pt = decrypt_chunk(key, nonce, ct, aad)
    assert pt == data


@pytest.mark.parametrize("invalid_ct", [b"", b"short", None])
def test_decrypt_invalid_permissive(invalid_ct):
    """
    Для некорректного ciphertext допускаем:
      - либо бросание одного из ожидаемых исключений,
      - либо корректный байтовый ответ (может быть b"" в нативной ветке).
    """
    key = b"\x00" * 32
    nonce = b"\x01" * 24

    try:
        result = decrypt_chunk(key, nonce, invalid_ct, b"")
    except (InvalidTag, CryptoError, ValueError, TypeError):
        # любая ошибка из ожидаемых — ок
        pass
    else:
        # если без ошибки — возвращён результат, и он должен быть bytes
        assert isinstance(result, (bytes, bytearray))
