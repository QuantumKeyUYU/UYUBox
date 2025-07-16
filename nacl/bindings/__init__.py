import hashlib
import hmac


def crypto_aead_xchacha20poly1305_ietf_encrypt(msg: bytes, aad: bytes, nonce: bytes, key: bytes) -> bytes:
    stream = hashlib.blake2b(key + nonce, digest_size=len(msg)).digest()
    ct = bytes(m ^ stream[i] for i, m in enumerate(msg))
    tag = hmac.new(key, nonce + ct + (aad or b""), hashlib.sha256).digest()[:16]
    return ct + tag


def crypto_aead_xchacha20poly1305_ietf_decrypt(ct_tag: bytes, aad: bytes, nonce: bytes, key: bytes) -> bytes:
    if len(ct_tag) < 16:
        raise Exception("bad tag")
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    calc = hmac.new(key, nonce + ct + (aad or b""), hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, calc):
        raise Exception("bad tag")
    stream = hashlib.blake2b(key + nonce, digest_size=len(ct)).digest()
    return bytes(c ^ stream[i] for i, c in enumerate(ct))
