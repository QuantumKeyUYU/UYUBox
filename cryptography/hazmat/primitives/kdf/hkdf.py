import hashlib


class HKDF:
    def __init__(self, algorithm, length, salt=None, info=b""):
        self.length = length
        self.salt = salt or b""
        self.info = info

    def derive(self, key_material: bytes) -> bytes:
        h = hashlib.sha256()
        h.update(key_material)
        h.update(self.info)
        h.update(self.salt)
        return h.digest()[: self.length]
