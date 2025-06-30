# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

__all__ = [
    "VDFVerificationError",
    "generate_posw_sha256",
    "prove_posw_sha256",
    "verify_posw_sha256",
]

# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import hashlib


class VDFVerificationError(Exception):
    """Общая ошибка Proof-of-Sequential-Work."""

    pass


def generate_posw_sha256(data: bytes, steps: int = 1) -> bytes:
    """
    Proof-of-Sequential-Work с SHA-256.
    По умолчанию steps=1, но можно задать любое положительное целое.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Seed must be bytes.")
    if not isinstance(steps, int) or steps <= 0:
        raise ValueError("Steps must be a positive integer.")
    h = data
    for _ in range(steps):
        h = hashlib.sha256(h).digest()
    return h


def verify_posw_sha256(data: bytes, proof: bytes, steps: int = 1) -> bool:
    """
    Проверяет, что generate_posw_sha256(data, steps) == proof.
    По умолчанию steps=1.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Seed must be bytes.")
    if not isinstance(steps, int) or steps <= 0:
        raise ValueError("Steps must be a positive integer.")
    if not isinstance(proof, (bytes, bytearray)) or len(proof) != hashlib.sha256(b"").digest_size:
        return False
    h = data
    for _ in range(steps):
        h = hashlib.sha256(h).digest()
    return h == proof


# Для совместимости с контейнером
prove_posw_sha256 = generate_posw_sha256
