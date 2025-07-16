import hashlib


class Poly1305:
    @staticmethod
    def generate_tag(key: bytes, data: bytes) -> bytes:
        return hashlib.blake2b(data, key=key, digest_size=16).digest()
