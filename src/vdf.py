import hashlib


def generate_proof(delay: int, data: bytes) -> bytes:
    """Return repeated SHA-256 of data ``delay`` times with delay encoded."""
    h = data
    for _ in range(delay):
        h = hashlib.sha256(h).digest()
    return delay.to_bytes(4, "big") + h


def verify_proof(proof: bytes, data: bytes) -> bool:
    """Validate proof created by :func:`generate_proof`."""
    if len(proof) < 4:
        return False
    delay = int.from_bytes(proof[:4], "big")
    expected = generate_proof(delay, data)
    return proof == expected
