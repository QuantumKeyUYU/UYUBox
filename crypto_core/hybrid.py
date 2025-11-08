"""Hybrid post-quantum aware encryption helpers."""
from __future__ import annotations

import itertools
import os
import struct
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .profiles import Argon2Profile, auto_calibrate, derive_key

try:  # pragma: no cover - optional dependency
    from pqcrypto.kem.kyber512 import generate_keypair, encrypt as pq_encrypt, decrypt as pq_decrypt
except Exception:  # pragma: no cover
    generate_keypair = None  # type: ignore
    pq_encrypt = None  # type: ignore
    pq_decrypt = None  # type: ignore

MAGIC = b"ZPQM"
VERSION = 1
HEADER_STRUCT = struct.Struct("!4sBIII")
CHUNK_SIZE = 256 * 1024


@dataclass
class HybridKeyMaterial:
    symmetric_key: bytes
    salt: bytes
    nonce: bytes
    kem_ciphertext: Optional[bytes] = None
    kem_public_key: Optional[bytes] = None


class HybridEncryptor:
    """Combine Argon2id KDF with Kyber (if available) and AES-GCM."""

    def __init__(self, profile: Argon2Profile | None = None) -> None:
        self.profile = profile or auto_calibrate()

    def build_key_material(
        self,
        password: str,
        *,
        kem_public_key: bytes | None = None,
        salt: bytes | None = None,
        nonce: bytes | None = None,
    ) -> HybridKeyMaterial:
        salt = salt or os.urandom(16)
        nonce = nonce or os.urandom(12)
        derived = derive_key(password, salt, profile=self.profile)
        if kem_public_key:
            if not pq_encrypt:  # pragma: no cover - environment dependent
                raise RuntimeError("Kyber KEM недоступен в окружении.")
            kem_ciphertext, shared_secret = pq_encrypt(kem_public_key)
            symmetric_key = bytes(
                (a ^ b)
                for a, b in itertools.zip_longest(derived, shared_secret, fillvalue=0)
            )
            return HybridKeyMaterial(
                symmetric_key=symmetric_key,
                salt=salt,
                nonce=nonce,
                kem_ciphertext=kem_ciphertext,
                kem_public_key=kem_public_key,
            )
        return HybridKeyMaterial(symmetric_key=derived, salt=salt, nonce=nonce)

    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        if not generate_keypair:
            raise RuntimeError("Kyber KEM недоступен в окружении.")
        return generate_keypair()

    def _xor_shared_secret(self, derived: bytes, shared_secret: bytes) -> bytes:
        return bytes(
            (a ^ b)
            for a, b in itertools.zip_longest(derived, shared_secret, fillvalue=0)
        )

    def encrypt_file(
        self,
        src_path: str,
        dest_path: str,
        password: str,
        *,
        kem_public_key: bytes | None = None,
        progress_cb: Callable[[float], None] | None = None,
        cancel_event: Optional[object] = None,
    ) -> HybridKeyMaterial:
        """Encrypt *src_path* into *dest_path* with streaming and cancellation."""

        material = self.build_key_material(password, kem_public_key=kem_public_key)
        kem_ciphertext = material.kem_ciphertext or b""
        kem_public_key = material.kem_public_key or b""

        header = HEADER_STRUCT.pack(
            MAGIC,
            VERSION,
            len(material.salt),
            len(kem_ciphertext),
            len(kem_public_key),
        )

        src_size = os.path.getsize(src_path)
        processed = 0

        def _report(progress: float) -> None:
            if progress_cb:
                progress_cb(min(max(progress, 0.0), 1.0))

        _report(0.0)

        cancel_flag = getattr(cancel_event, "is_set", None)

        tmp_dir = os.path.dirname(os.path.abspath(dest_path)) or None
        tmp_file = None

        try:
            with open(src_path, "rb") as src, tempfile.NamedTemporaryFile(
                "wb", dir=tmp_dir, delete=False
            ) as tmp:
                tmp_file = tmp.name
                tmp.write(material.nonce)
                tmp.write(header)
                tmp.write(material.salt)
                tmp.write(kem_ciphertext)
                tmp.write(kem_public_key)

                cipher = Cipher(
                    algorithms.AES(material.symmetric_key),
                    modes.GCM(material.nonce),
                )
                encryptor = cipher.encryptor()

                while True:
                    if cancel_flag and cancel_flag():
                        raise RuntimeError("Операция отменена")
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    processed += len(chunk)
                    tmp.write(encryptor.update(chunk))
                    if src_size:
                        _report(processed / src_size)

                if cancel_flag and cancel_flag():
                    raise RuntimeError("Операция отменена")

                tmp.write(encryptor.finalize())
                tmp.write(encryptor.tag)

                if cancel_flag and cancel_flag():
                    raise RuntimeError("Операция отменена")

            os.replace(tmp_file, dest_path)
            _report(1.0)
            return material
        except Exception:
            if tmp_file and os.path.exists(tmp_file):
                try:
                    os.unlink(tmp_file)
                except OSError:
                    pass
            raise

    def decrypt_file(
        self,
        src_path: str,
        dest_path: str,
        password: str,
        *,
        kem_private_key: bytes | None = None,
        progress_cb: Callable[[float], None] | None = None,
        cancel_event: Optional[object] = None,
    ) -> None:
        """Decrypt *src_path* into *dest_path* validating headers and tag."""

        cancel_flag = getattr(cancel_event, "is_set", None)

        def _report(progress: float) -> None:
            if progress_cb:
                progress_cb(min(max(progress, 0.0), 1.0))

        _report(0.0)

        with open(src_path, "rb") as src:
            nonce = src.read(12)
            if len(nonce) != 12:
                raise ValueError("Контейнер повреждён: отсутствует nonce")
            header_data = src.read(HEADER_STRUCT.size)
            if len(header_data) != HEADER_STRUCT.size:
                raise ValueError("Контейнер повреждён: заголовок усечён")
            magic, version, salt_len, kem_cipher_len, kem_pub_len = HEADER_STRUCT.unpack(header_data)
            if magic != MAGIC:
                raise ValueError("Неизвестный формат контейнера")
            if version != VERSION:
                raise ValueError("Неподдерживаемая версия контейнера")
            salt = src.read(salt_len)
            if len(salt) != salt_len:
                raise ValueError("Контейнер повреждён: соль усечена")
            kem_ciphertext = src.read(kem_cipher_len)
            if len(kem_ciphertext) != kem_cipher_len:
                raise ValueError("Контейнер повреждён: гибридные данные усечены")
            kem_public_key = src.read(kem_pub_len)
            if len(kem_public_key) != kem_pub_len:
                raise ValueError("Контейнер повреждён: публичный ключ усечён")

            payload_start = src.tell()
            file_size = os.path.getsize(src_path)
            if file_size < payload_start + 16:
                raise ValueError("Контейнер повреждён: отсутствует тег аутентичности")
            ciphertext_len = file_size - payload_start - 16
            src.seek(file_size - 16)
            tag = src.read(16)
            if len(tag) != 16:
                raise ValueError("Контейнер повреждён: тег усечён")
            src.seek(payload_start)

            derived = derive_key(password, salt, profile=self.profile)
            if kem_cipher_len:
                if not kem_private_key or not pq_decrypt:
                    raise ValueError("Требуется приватный ключ Kyber для расшифровки")
                shared_secret = pq_decrypt(kem_private_key, kem_ciphertext)
                symmetric_key = self._xor_shared_secret(derived, shared_secret)
            else:
                symmetric_key = derived

            cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            processed = 0
            tmp_dir = os.path.dirname(os.path.abspath(dest_path)) or None
            tmp_file = None
            try:
                with tempfile.NamedTemporaryFile("wb", dir=tmp_dir, delete=False) as tmp:
                    tmp_file = tmp.name
                    while processed < ciphertext_len:
                        if cancel_flag and cancel_flag():
                            raise RuntimeError("Операция отменена")
                        to_read = min(CHUNK_SIZE, ciphertext_len - processed)
                        chunk = src.read(to_read)
                        if len(chunk) != to_read:
                            raise ValueError("Контейнер повреждён: данные усечены")
                        processed += len(chunk)
                        tmp.write(decryptor.update(chunk))
                        if ciphertext_len:
                            _report(processed / ciphertext_len)
                    if cancel_flag and cancel_flag():
                        raise RuntimeError("Операция отменена")
                    tmp.write(decryptor.finalize())

                if cancel_flag and cancel_flag():
                    raise RuntimeError("Операция отменена")

                os.replace(tmp_file, dest_path)
                _report(1.0)
            except Exception:
                if tmp_file and os.path.exists(tmp_file):
                    try:
                        os.unlink(tmp_file)
                    except OSError:
                        pass
                raise


__all__ = ["HybridEncryptor", "HybridKeyMaterial"]
