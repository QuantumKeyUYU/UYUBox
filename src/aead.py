# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import Tuple, cast

DEFAULT_KEY_LENGTH = 32
DEFAULT_NONCE_LENGTH = 12
DEFAULT_TAG_LENGTH = 16


class AEADInvalidTagError(Exception):
    pass


def encrypt_chacha20_poly1305(key: bytes, nonce: bytes, payload: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Key must be bytes.")
    if len(key) != DEFAULT_KEY_LENGTH:
        raise ValueError(f"Key must be {DEFAULT_KEY_LENGTH} bytes long.")
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError("Nonce must be bytes.")
    if len(nonce) != DEFAULT_NONCE_LENGTH:
        raise ValueError(f"Nonce must be {DEFAULT_NONCE_LENGTH} bytes long.")
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Payload must be bytes.")
    if not isinstance(aad, (bytes, bytearray)):
        raise TypeError("AAD must be bytes.")

    ch = ChaCha20Poly1305(key)
    ct_and_tag = ch.encrypt(nonce, payload, aad)
    return ct_and_tag[:-DEFAULT_TAG_LENGTH], ct_and_tag[-DEFAULT_TAG_LENGTH:]


def decrypt_chacha20_poly1305(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Key must be bytes.")
    if len(key) != DEFAULT_KEY_LENGTH:
        raise ValueError(f"Key must be {DEFAULT_KEY_LENGTH} bytes long.")
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError("Nonce must be bytes.")
    if len(nonce) != DEFAULT_NONCE_LENGTH:
        raise ValueError(f"Nonce must be {DEFAULT_NONCE_LENGTH} bytes long.")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext must be bytes.")
    if not isinstance(tag, (bytes, bytearray)):
        raise TypeError("Tag must be bytes.")
    if len(tag) != DEFAULT_TAG_LENGTH:
        raise ValueError(f"Tag must be {DEFAULT_TAG_LENGTH} bytes long.")
    if not isinstance(aad, (bytes, bytearray)):
        raise TypeError("AAD must be bytes.")

    ch = ChaCha20Poly1305(key)
    try:
        return cast(bytes, ch.decrypt(nonce, ciphertext + tag, aad))
    except InvalidTag:
        raise AEADInvalidTagError("Invalid authentication tag.")
    except Exception as e:
        raise AEADInvalidTagError(str(e))


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != DEFAULT_KEY_LENGTH:
        raise ValueError("key must be 32 bytes long")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if not isinstance(aad, (bytes, bytearray)):
        raise TypeError("aad must be bytes")

    nonce = os.urandom(DEFAULT_NONCE_LENGTH)
    ch = ChaCha20Poly1305(key)
    ct = ch.encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError("key must be 32 bytes long")
    if len(key) != DEFAULT_KEY_LENGTH:
        raise ValueError("key must be 32 bytes long")
    if not isinstance(nonce, (bytes, bytearray)):
        raise ValueError("nonce must be 12 bytes long")
    if len(nonce) != DEFAULT_NONCE_LENGTH:
        raise ValueError("nonce must be 12 bytes long")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    if not isinstance(aad, (bytes, bytearray)):
        raise TypeError("aad must be bytes")

    ch = ChaCha20Poly1305(key)
    return cast(bytes, ch.decrypt(nonce, ciphertext, aad))


class PQAEAD:
    _NONCE_LEN = DEFAULT_NONCE_LENGTH

    @staticmethod
    def encrypt(public_key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        from .utils.pq_crypto import Kyber768KEM, derive_key_pq

        if not isinstance(public_key, (bytes, bytearray)):
            raise TypeError("public_key must be bytes")
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes")

        kem = Kyber768KEM()
        ct_kem, shared = kem.encapsulate(public_key)
        key = derive_key_pq(shared)
        nonce = os.urandom(PQAEAD._NONCE_LEN)
        ch = ChaCha20Poly1305(key)
        ct = ch.encrypt(nonce, plaintext, aad)
        return cast(bytes, ct_kem + nonce + ct)

    @staticmethod
    def decrypt(private_key: bytes, payload: bytes, aad: bytes = b"") -> bytes:
        from .utils.pq_crypto import Kyber768KEM, derive_key_pq

        if not isinstance(private_key, (bytes, bytearray)):
            raise TypeError("private_key must be bytes")
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError("aad must be bytes")

        kem = Kyber768KEM()
        ct_len = kem.ciphertext_length()
        kem_ct = payload[:ct_len]
        nonce = payload[ct_len : ct_len + PQAEAD._NONCE_LEN]
        ct = payload[ct_len + PQAEAD._NONCE_LEN :]
        shared = kem.decapsulate(private_key, kem_ct)
        key = derive_key_pq(shared)
        ch = ChaCha20Poly1305(key)
        return cast(bytes, ch.decrypt(nonce, ct, aad))
