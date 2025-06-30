"""
Гибридные (post-quantum + classic) криптопримитивы.
"""

from __future__ import annotations

import os
import typing as _t
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import cast

from zilant_prime_core.utils.pq_crypto import HybridKEM

# --------------------------------------------------------------------------- #
#  Hybrid KEM (Kyber + XChaCha20-Poly1305)                                    #
# --------------------------------------------------------------------------- #


def hybrid_encrypt(
    recipient_pk: tuple[bytes, bytes],
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    kem = HybridKEM()
    ct_pq, _ss, epk, _ek, shared = kem.encapsulate(recipient_pk)

    nonce = os.urandom(12)
    cipher = cast(bytes, ChaCha20Poly1305(shared).encrypt(nonce, plaintext, aad))

    return b"".join((ct_pq, epk, nonce)), cipher


def hybrid_decrypt(  # noqa: D401
    recipient_sk: tuple[bytes, bytes],
    encapsulation: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
) -> bytes:
    kem = HybridKEM()
    ct_pq, epk, nonce = encapsulation[:-44], encapsulation[-44:-12], encapsulation[-12:]
    shared = kem.decapsulate(recipient_sk, (ct_pq, epk, b""))

    return cast(bytes, ChaCha20Poly1305(shared).decrypt(nonce, ciphertext, aad))


# --------------------------------------------------------------------------- #
#            Комбинированная подпись (Ed25519 + Dilithium-3)                  #
# --------------------------------------------------------------------------- #

try:
    from pqclean.branchfree import dilithium3  # type: ignore
except ImportError:  # pragma: no cover
    try:
        from pqclean import dilithium3  # type: ignore
    except ImportError:  # pragma: no cover
        dilithium3 = None  # type: ignore


def _require_dilithium() -> None:
    if dilithium3 is None:  # pragma: no cover
        raise RuntimeError("pqclean.dilithium3 not installed")


def dual_sign(msg: bytes, ed_sk: bytes, pq_sk: bytes) -> bytes:
    """
    Вернуть слепок Ed25519- + Dilithium-подписей.

    *Если Dilithium недоступен*, вызывающий код должен перехватить
    RuntimeError — тесты это уже делают.
    """
    ed_sig: bytes = ed25519.Ed25519PrivateKey.from_private_bytes(ed_sk).sign(msg)

    _require_dilithium()
    pq_sig: bytes = _t.cast(bytes, dilithium3.sign(msg, pq_sk))  # type: ignore

    return ed_sig + pq_sig  # bytes + bytes ⇒ bytes (mypy счастлив)


def dual_verify(msg: bytes, sig: bytes, ed_pk: bytes, pq_pk: bytes) -> bool:
    """Проверить гибридную подпись. False — при любой ошибке."""
    if len(sig) < 64:
        return False

    sig_ed, sig_pq = sig[:64], sig[64:]

    try:
        ed25519.Ed25519PublicKey.from_public_bytes(ed_pk).verify(sig_ed, msg)
    except Exception:
        return False

    _require_dilithium()
    try:
        return bool(dilithium3.verify(msg, sig_pq, pq_pk))  # type: ignore
    except Exception:
        return False
