import hmac


class HKDF:
    def __init__(self, algorithm, length, salt=None, info=b""):
        self.algorithm = algorithm
        self.length = length
        self.salt = salt or b"".rjust(algorithm().digest_size, b"\0")
        self.info = info

    def derive(self, key_material: bytes) -> bytes:
        prk = hmac.new(self.salt, key_material, self.algorithm).digest()
        t = b""
        okm = b""
        counter = 1
        while len(okm) < self.length:
            t = hmac.new(prk, t + self.info + bytes([counter]), self.algorithm).digest()
            okm += t
            counter += 1
        return okm[: self.length]
