# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Post-quantum cryptography helpers."""

from __future__ import annotations

import abc
from typing import Tuple, cast

try:
    import oqs
except Exception:  # pragma: no cover - optional dependency
    oqs = None

try:
    from pqclean.branchfree import dilithium2 as dilithium2
    from pqclean.branchfree import kyber768 as kyber768
except Exception:  # pragma: no cover - optional dependency
    try:
        from pqclean import dilithium2, kyber768
    except Exception:  # pragma: no cover - optional dependency
        kyber768 = None
        dilithium2 = None

from kdf import derive_key


class KEM(abc.ABC):
    """Abstract interface for key encapsulation mechanisms."""

    @abc.abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Return (public_key, private_key)."""

    @abc.abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate public_key and return (ciphertext, shared_secret)."""

    @abc.abstractmethod
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate ciphertext using private_key and return shared_secret."""


class SignatureScheme(abc.ABC):
    """Abstract interface for digital signature schemes."""

    @abc.abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Return (public_key, private_key)."""

    @abc.abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Return signature for message."""

    @abc.abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify signature for message."""


class Kyber768KEM(KEM):
    """Kyber768 KEM implementation via pqclean."""

    def __init__(self) -> None:
        if kyber768 is None:
            raise RuntimeError("pqclean.kyber768 not installed")

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        pk, sk = cast(Tuple[bytes, bytes], kyber768.generate_keypair())  # pragma: no cover - heavy
        return pk, sk  # pragma: no cover - heavy

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        ct, ss = cast(Tuple[bytes, bytes], kyber768.encapsulate(public_key))  # pragma: no cover - heavy
        return ct, ss  # pragma: no cover - heavy

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        return kyber768.decapsulate(ciphertext, private_key)  # type: ignore[no-any-return]

    @staticmethod
    def ciphertext_length() -> int:
        return getattr(
            kyber768,
            "CIPHERTEXT_SIZE",
            len(kyber768.encapsulate(kyber768.generate_keypair()[0])[0]),
        )  # pragma: no cover - heavy


class Dilithium2Signature(SignatureScheme):
    """Dilithium2 signature scheme via pqclean."""

    def __init__(self) -> None:
        if dilithium2 is None:  # pragma: no cover - optional
            raise RuntimeError("pqclean.dilithium2 not installed")  # pragma: no cover

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        pk, sk = cast(Tuple[bytes, bytes], dilithium2.generate_keypair())  # pragma: no cover - heavy
        return pk, sk  # pragma: no cover - heavy

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return dilithium2.sign(message, private_key)  # type: ignore[no-any-return]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:  # pragma: no cover - verification
            return dilithium2.verify(message, signature, public_key)  # type: ignore[no-any-return]
        except Exception:  # pragma: no cover - invalid sig
            return False


class FalconSig(SignatureScheme):
    """Falcon signature via pqclean."""

    def __init__(self) -> None:
        try:
            from pqclean.branchfree import falcon1024 as falcon
        except Exception:  # pragma: no cover - optional
            try:
                from pqclean import falcon1024 as falcon  # type: ignore
            except Exception:  # pragma: no cover - optional
                falcon = None
        if falcon is None:
            raise RuntimeError("Falcon not installed")
        self._falcon = falcon

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return cast(Tuple[bytes, bytes], self._falcon.generate_keypair())

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return self._falcon.sign(message, private_key)  # type: ignore[no-any-return]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return self._falcon.verify(message, signature, public_key)  # type: ignore[no-any-return]
        except Exception:
            return False


class SphincsSig(SignatureScheme):
    """SPHINCS+ signature via pqclean."""

    def __init__(self) -> None:
        try:
            from pqclean.branchfree import sphincsplus_sha256_128f_simple as sphincs
        except Exception:  # pragma: no cover - optional
            try:
                from pqclean import sphincsplus_sha256_128f_simple as sphincs  # type: ignore
            except Exception:
                sphincs = None
        if sphincs is None:
            raise RuntimeError("SPHINCS+ not installed")
        self._sphincs = sphincs

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return cast(Tuple[bytes, bytes], self._sphincs.generate_keypair())

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return self._sphincs.sign(message, private_key)  # type: ignore[no-any-return]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return self._sphincs.verify(message, signature, public_key)  # type: ignore[no-any-return]
        except Exception:
            return False


class OQSKyberKEM(KEM):
    """Kyber768 KEM via liboqs if available."""

    def __init__(self) -> None:
        if oqs is None:  # pragma: no cover - optional
            raise RuntimeError("liboqs not installed")  # pragma: no cover
        self._kem = oqs.KeyEncapsulation("Kyber768")  # pragma: no cover

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return self._kem.generate_keypair()  # type: ignore[no-any-return]

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        return self._kem.encapsulate(public_key)  # type: ignore[no-any-return]

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        return self._kem.decapsulate(ciphertext, private_key)  # type: ignore[no-any-return]

    def ciphertext_length(self) -> int:
        return self._kem.details.length_ciphertext  # type: ignore[no-any-return]


class HybridKEM(KEM):
    """Hybrid KEM combining Kyber768 and X25519."""

    def __init__(self) -> None:
        self._pq = Kyber768KEM()
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import x25519
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        except Exception:  # pragma: no cover - optional dependency
            raise RuntimeError("cryptography not installed")
        self._x25519 = x25519
        self._hkdf = HKDF
        self._hashes = hashes
        self._serialization = serialization

    def generate_keypair(self) -> Tuple[bytes, bytes, bytes, bytes]:  # type: ignore[override]
        pk_pq, sk_pq = self._pq.generate_keypair()
        sk_x = self._x25519.X25519PrivateKey.generate()
        pk_x = sk_x.public_key().public_bytes(
            self._serialization.Encoding.Raw,
            self._serialization.PublicFormat.Raw,
        )
        sk_x_bytes = sk_x.private_bytes(
            self._serialization.Encoding.Raw,
            self._serialization.PrivateFormat.Raw,
            self._serialization.NoEncryption(),
        )
        return pk_pq, sk_pq, pk_x, sk_x_bytes

    def encapsulate(  # type: ignore[override]
        self, public_key: Tuple[bytes, bytes]
    ) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
        pk_pq, pk_x = public_key
        ct_pq, ss_pq = self._pq.encapsulate(pk_pq)
        ephem_sk = self._x25519.X25519PrivateKey.generate()
        ephem_pk = ephem_sk.public_key().public_bytes(
            self._serialization.Encoding.Raw,
            self._serialization.PublicFormat.Raw,
        )
        pk_x_obj = self._x25519.X25519PublicKey.from_public_bytes(pk_x)
        ss_x = ephem_sk.exchange(pk_x_obj)
        hkdf = self._hkdf(
            algorithm=self._hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid",
        )
        shared: bytes = hkdf.derive(ss_pq + ss_x)
        return ct_pq, ss_pq, ephem_pk, ss_x, shared

    def decapsulate(  # type: ignore[override]
        self, private_key: Tuple[bytes, bytes], ciphertext: Tuple[bytes, bytes, bytes]
    ) -> bytes:
        sk_pq, sk_x_bytes = private_key
        ct_pq, ephem_pk, _ = ciphertext
        ss_pq = self._pq.decapsulate(sk_pq, ct_pq)
        sk_x = self._x25519.X25519PrivateKey.from_private_bytes(sk_x_bytes)
        ephem_pk_obj = self._x25519.X25519PublicKey.from_public_bytes(ephem_pk)
        ss_x = sk_x.exchange(ephem_pk_obj)
        hkdf = self._hkdf(
            algorithm=self._hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid",
        )
        shared: bytes = hkdf.derive(ss_pq + ss_x)
        return shared


def derive_key_pq(shared_secret: bytes, length: int = 32) -> bytes:
    """Derive a symmetric key from a KEM shared secret."""

    if not isinstance(shared_secret, (bytes, bytearray)):
        raise TypeError("shared_secret must be bytes or bytearray")

    key: bytes = derive_key(bytes(shared_secret), b"pq_salt!")
    return key[:length]
