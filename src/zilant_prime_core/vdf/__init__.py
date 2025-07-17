# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# src/zilant_prime_core/vdf/__init__.py

from .phase_vdf import VDFVerificationError, generate_elc_vdf, generate_landscape, verify_elc_vdf, verify_landscape

__all__ = [
    "generate_elc_vdf",
    "verify_elc_vdf",
    "generate_landscape",
    "verify_landscape",
    "VDFVerificationError",
]
from .vdf import generate_posw_sha256, verify_posw_sha256


def posw(seed: bytes, steps: int = 1):
    proof = generate_posw_sha256(seed, steps)
    return proof, True


def check_posw(proof: bytes, seed: bytes, steps: int = 1) -> bool:
    return verify_posw_sha256(seed, proof, steps)


__all__ += ["posw", "check_posw"]
