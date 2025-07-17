import hashlib


class SHA256:
    """Lightweight SHA256 stand in."""

    name = "sha256"
    digest_size = hashlib.sha256().digest_size
    block_size = hashlib.sha256().block_size

    def __call__(self) -> hashlib._hashlib.HASH:
        return hashlib.sha256()
