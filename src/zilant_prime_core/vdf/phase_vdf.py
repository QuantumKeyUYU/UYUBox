# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

__all__ = [
    "VDFVerificationError",
    "generate_elc_vdf",
    "generate_landscape",
    "generate_posw_sha256",
    "prove_posw_sha256",
    "verify_elc_vdf",
    "verify_landscape",
    "verify_posw_sha256",
]

# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

"""
Elementary (hash-chain) VDF based on SHA-256.

Сохраняем обратную совместимость:
    • generate_elc_vdf / verify_elc_vdf
    • generate_posw_sha256 / verify_posw_sha256 / prove_posw_sha256
    • generate_landscape  / verify_landscape
"""

import hashlib

# ─────────────────────────── exceptions ──────────────────────────────


class VDFVerificationError(Exception):
    """Raised only при явном строгом запросе verify(..., strict=True)."""


# ──────────────────────────── helpers ────────────────────────────────


def _validate_seed(seed: bytes | bytearray) -> bytes:
    if not isinstance(seed, (bytes, bytearray)):
        raise ValueError("Seed must be bytes.")
    return bytes(seed)


def _validate_steps(steps: int) -> int:
    if not isinstance(steps, int) or steps <= 0:
        raise ValueError("Steps must be a positive integer.")
    return steps


def _validate_proof(proof: bytes | bytearray) -> bytes:
    if not isinstance(proof, (bytes, bytearray)):
        raise ValueError("Proof must be bytes.")
    proof_b = bytes(proof)
    if len(proof_b) != hashlib.sha256().digest_size:
        raise ValueError("Proof has wrong length.")
    return proof_b


# ─────────────────────────── core engine ─────────────────────────────


def generate_elc_vdf(seed: bytes, steps: int) -> bytes:
    """SHA-256 применяется *steps* раз к *seed*. Возвращает итоговый digest."""
    seed_b = _validate_seed(seed)
    steps = _validate_steps(steps)

    h = seed_b
    for _ in range(steps):
        h = hashlib.sha256(h).digest()
    return h


def verify_elc_vdf(
    seed: bytes,
    steps: int,
    proof: bytes,
    *,
    strict: bool = False,
) -> bool:
    """
    Проверяет корректность *proof* для пары (*seed*, *steps*).

    • Возвращает **True** / **False** (старое поведение),
    • Если нужен именно exception — передайте `strict=True`.
    """
    seed_b = _validate_seed(seed)
    steps = _validate_steps(steps)
    proof_b = _validate_proof(proof)

    ok = generate_elc_vdf(seed_b, steps) == proof_b
    if not ok and strict:
        raise VDFVerificationError("Proof does not match seed/steps.")
    return ok


# ──────────────────────────── aliases ────────────────────────────────
# Эти имена «жили» в публичном API и в тестах — сохраняем их.

generate_posw_sha256 = generate_elc_vdf
prove_posw_sha256 = generate_elc_vdf  # property-tests


def verify_posw_sha256(seed: bytes, proof: bytes, steps: int) -> bool:
    # порядок аргументов «seed, proof, steps» — исторически так сложилось
    return verify_elc_vdf(seed, steps, proof)


def generate_landscape(seed: bytes, steps: int) -> bytes:
    return generate_elc_vdf(seed, steps)


def verify_landscape(seed: bytes, steps: int, proof: bytes) -> bool:
    return verify_elc_vdf(seed, steps, proof)
