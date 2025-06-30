#!/usr/bin/env python3
from __future__ import annotations

import sys

try:
    import atheris
except Exception:  # pragma: no cover - optional fuzz dep
    print("Atheris not installed; skipping fuzz")
    raise SystemExit(0)

from zilant_prime_core.crypto import aead
from zilant_prime_core.utils import self_watchdog
from zilant_prime_core.vdf import phase_vdf


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    key = fdp.ConsumeBytes(32) or b"0" * 32
    nonce = fdp.ConsumeBytes(12) or b"0" * 12
    payload = fdp.ConsumeBytes(40)
    try:
        ct = aead.encrypt_aead(key[:32], nonce[:12], payload)
        aead.decrypt_aead(key[:32], nonce[:12], ct)
    except Exception:
        pass

    seed = fdp.ConsumeBytes(8)
    steps = fdp.ConsumeIntInRange(1, 3)
    proof = phase_vdf.generate_elc_vdf(seed, steps)
    phase_vdf.verify_elc_vdf(seed, steps, proof)

    path = fdp.ConsumeString(5)
    try:
        self_watchdog.compute_self_hash(path)
    except Exception:
        pass


def main() -> None:
    if "--ci" in sys.argv:
        sys.argv.remove("--ci")
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
