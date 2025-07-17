import hashlib
import hmac


def crypto_aead_xchacha20poly1305_ietf_encrypt(msg: bytes, aad: bytes, nonce: bytes, key: bytes) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < len(msg):
        stream.extend(hashlib.blake2b(key + nonce + counter.to_bytes(4, "little")).digest())
        counter += 1
    stream = bytes(stream[: len(msg)])
    ct = bytes(m ^ stream[i] for i, m in enumerate(msg))
    tag = hmac.new(key, nonce + ct + (aad or b""), hashlib.sha256).digest()[:16]
    return ct + tag


def crypto_aead_xchacha20poly1305_ietf_decrypt(ct_tag: bytes, aad: bytes, nonce: bytes, key: bytes) -> bytes:
    if len(ct_tag) < 16:
        raise ValueError("bad tag")
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    calc = hmac.new(key, nonce + ct + (aad or b""), hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, calc):
        raise ValueError("bad tag")
    stream = bytearray()
    counter = 0
    while len(stream) < len(ct):
        stream.extend(hashlib.blake2b(key + nonce + counter.to_bytes(4, "little")).digest())
        counter += 1
    stream = bytes(stream[: len(ct)])
    return bytes(c ^ stream[i] for i, c in enumerate(ct))
