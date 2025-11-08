"""Hybrid post-quantum aware encryption helpers."""
from __future__ import annotations

import itertools
import os
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .profiles import Argon2Profile, auto_calibrate, derive_key

try:  # pragma: no cover - optional dependency
    from pqcrypto.kem.kyber512 import generate_keypair, encrypt as pq_encrypt, decrypt as pq_decrypt
except Exception:  # pragma: no cover
    generate_keypair = None  # type: ignore
    pq_encrypt = None  # type: ignore
    pq_decrypt = None  # type: ignore

HEADER_STRUCT = struct.Struct("!II")


@dataclass
class HybridKeyMaterial:
    symmetric_key: bytes
    kem_ciphertext: Optional[bytes] = None
    kem_public_key: Optional[bytes] = None


class HybridEncryptor:
    """Combine Argon2id KDF with Kyber (if available) and AES-GCM."""

    def __init__(self, profile: Argon2Profile | None = None) -> None:
        self.profile = profile or auto_calibrate()

    def build_key_material(self, password: str, *, kem_public_key: bytes | None = None) -> HybridKeyMaterial:
        salt = os.urandom(16)
        derived = derive_key(password, salt, profile=self.profile)
        if kem_public_key and pq_encrypt:
            kem_ciphertext, shared_secret = pq_encrypt(kem_public_key)
            symmetric_key = bytes(
                (a ^ b)
                for a, b in itertools.zip_longest(derived, shared_secret, fillvalue=0)
            )
            return HybridKeyMaterial(
                symmetric_key=symmetric_key,
                kem_ciphertext=kem_ciphertext,
                kem_public_key=kem_public_key,
            )
        return HybridKeyMaterial(symmetric_key=derived)

    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        if not generate_keypair:
            raise RuntimeError("Kyber KEM недоступен в окружении.")
        return generate_keypair()

    def encrypt_file(
        self,
        src_path: str,
        dest_path: str,
        password: str,
        *,
        kem_public_key: bytes | None = None,
        progress_cb: Callable[[float], None] | None = None,
    ) -> HybridKeyMaterial:
        material = self.build_key_material(password, kem_public_key=kem_public_key)
        aesgcm = AESGCM(material.symmetric_key)
        nonce = os.urandom(12)
        kem_ciphertext = material.kem_ciphertext or b""
        kem_public_key = material.kem_public_key or b""
        header = HEADER_STRUCT.pack(len(kem_ciphertext), len(kem_public_key))
        with open(src_path, "rb") as src:
            plaintext = src.read()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        with open(dest_path, "wb") as dest:
            dest.write(nonce)
            dest.write(header)
            dest.write(kem_ciphertext)
            dest.write(kem_public_key)
            dest.write(ciphertext)
        if progress_cb:
            progress_cb(0.5)
            progress_cb(1.0)
        return material

    def decrypt_file(
        self,
        src_path: str,
        dest_path: str,
        password: str,
        *,
        kem_private_key: bytes | None = None,
        progress_cb: Callable[[float], None] | None = None,
    ) -> None:
        with open(src_path, "rb") as src:
            nonce = src.read(12)
            header_data = src.read(HEADER_STRUCT.size)
            if len(header_data) != HEADER_STRUCT.size:
                raise ValueError("Формат контейнера повреждён")
            kem_cipher_len, kem_pub_len = HEADER_STRUCT.unpack(header_data)
            kem_ciphertext = src.read(kem_cipher_len)
            kem_public_key = src.read(kem_pub_len)
            ciphertext = src.read()
        if kem_ciphertext and kem_private_key and pq_decrypt:
            shared_secret = pq_decrypt(kem_private_key, kem_ciphertext)
            derived = derive_key(password, nonce, profile=self.profile)
            symmetric_key = bytes(
                (a ^ b)
                for a, b in itertools.zip_longest(derived, shared_secret, fillvalue=0)
            )
        else:
            symmetric_key = derive_key(password, nonce, profile=self.profile)
        aesgcm = AESGCM(symmetric_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        with open(dest_path, "wb") as dest:
            dest.write(plaintext)
        if progress_cb:
            progress_cb(0.5)
            progress_cb(1.0)


__all__ = ["HybridEncryptor", "HybridKeyMaterial"]
