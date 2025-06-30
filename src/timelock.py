from __future__ import annotations

import hashlib
import json
from itertools import cycle
from pathlib import Path

from vdf import generate_proof, verify_proof


def _xor_data(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ k for b, k in zip(data, cycle(key)))


def lock_file(input_path: str, output_path: str, delay: int) -> None:
    """Encrypt *input_path* under a time lock.

    Parameters
    ----------
    input_path: str
        Path to the plaintext file.
    output_path: str
        Where to save the locked container.
    delay: int
        Number of sequential hash steps.
    """
    src = Path(input_path).read_bytes()
    digest = hashlib.sha256(src).digest()
    proof = generate_proof(delay, digest)
    header = {"delay": delay, "proof": proof.hex()}
    key = hashlib.sha256(proof).digest()
    payload = _xor_data(src, key)
    Path(output_path).write_bytes(json.dumps(header).encode() + b"\n" + payload)


def unlock_file(input_path: str, output_path: str) -> None:
    """Unlock *input_path* created by :func:`lock_file`."""
    blob = Path(input_path).read_bytes()
    sep = blob.find(b"\n")
    if sep == -1:
        raise ValueError("Invalid timelock container")
    header = json.loads(blob[:sep].decode())
    proof = bytes.fromhex(header["proof"])
    payload = blob[sep + 1 :]
    key = hashlib.sha256(proof).digest()
    data = _xor_data(payload, key)
    digest = hashlib.sha256(data).digest()
    if not verify_proof(proof, digest):
        raise ValueError("Proof verification failed")
    Path(output_path).write_bytes(data)
