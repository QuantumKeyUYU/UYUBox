from __future__ import annotations

import hashlib
import json
import os
import time
import zstandard as zstd

try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305 as _NativeAEAD
except ImportError:  # pragma: no cover - fallback
    _NativeAEAD = None  # type: ignore[assignment]
from cryptography.hazmat.primitives.poly1305 import Poly1305
from pathlib import Path
from typing import IO, List, cast

CHUNK = 4 * 1024 * 1024
NONCE_SZ = 24
TAG_SZ = 16


def _derive_nonce(chunk_id: int, key: bytes) -> bytes:
    data = chunk_id.to_bytes(8, "little")
    return hashlib.blake2b(data, key=key, digest_size=NONCE_SZ).digest()


def encrypt_chunk(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if _NativeAEAD is not None:
        ct = _NativeAEAD(key).encrypt(nonce, data, aad)
    else:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

        ct = crypto_aead_xchacha20poly1305_ietf_encrypt(data, aad, nonce, key)
    return cast(bytes, ct)


def decrypt_chunk(key: bytes, nonce: bytes, cipher: bytes, aad: bytes = b"") -> bytes:
    if _NativeAEAD is not None:
        pt = _NativeAEAD(key).decrypt(nonce, cipher, aad)
    else:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

        pt = crypto_aead_xchacha20poly1305_ietf_decrypt(cipher, aad, nonce, key)
    return cast(bytes, pt)


def _tree_mac(tags: List[bytes], key: bytes) -> bytes:
    nodes = tags[:]
    while len(nodes) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else b""
            nxt.append(Poly1305.generate_tag(key, left + right))
        nodes = nxt
    return nodes[0] if nodes else Poly1305.generate_tag(key, b"")


def pack_stream(src: Path, dst: Path, key: bytes, threads: int = 0, progress: bool = False) -> None:
    comp = zstd.ZstdCompressor(level=3, threads=threads or 0)
    tags: List[bytes] = []
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    with open(src, "rb") as f_in, open(tmp, "wb") as f_out:
        chunk_id = 0
        size = 0
        while True:
            chunk = f_in.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            cdata = comp.compress(chunk)
            nonce = _derive_nonce(chunk_id, key)
            cipher = encrypt_chunk(key, nonce, cdata)
            tags.append(cipher[-TAG_SZ:])
            f_out.write(len(cipher).to_bytes(4, "big"))
            f_out.write(cipher)
            chunk_id += 1
    root = _tree_mac(tags, key)
    meta = {
        "magic": "ZSTR",
        "version": 1,
        "chunks": len(tags),
        "root_tag": root.hex(),
        "orig_size": size,
    }
    header = json.dumps(meta).encode("utf-8") + b"\n\n"
    with open(dst, "wb") as final, open(tmp, "rb") as f_out:
        final.write(header)
        while True:
            buf = f_out.read(65536)
            if not buf:
                break
            final.write(buf)
    os.remove(tmp)


def _read_exact(fh: IO[bytes], n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = fh.read(n - len(buf))
        if not chunk:
            time.sleep(0.05)
            continue
        buf.extend(chunk)
    return bytes(buf)


def resume_decrypt(path: Path, key: bytes, have_bytes: int, out_path: Path, offset: int = 0) -> None:
    """Resume decrypting *path* once at least 51 % is present.

    ``offset`` skips the first ``offset`` bytes of ciphertext (plus header)
    before writing plaintext. Data integrity is verified against the tree
    MAC embedded in the header.
    """

    total = os.path.getsize(path)
    if have_bytes < total * 0.51:
        raise ValueError("insufficient data for resume")

    with open(path, "rb") as f_in:
        header = bytearray()
        while not header.endswith(b"\n\n"):
            header.extend(_read_exact(f_in, 1))
        meta = json.loads(header[:-2].decode("utf-8"))
        root_tag = bytes.fromhex(meta["root_tag"])
        chunk_count = meta["chunks"]
        tags: List[bytes] = []
        pos = len(header)

        with open(out_path, "wb") as f_out:
            for cid in range(chunk_count):
                clen = int.from_bytes(_read_exact(f_in, 4), "big")
                cipher = _read_exact(f_in, clen)
                nonce = _derive_nonce(cid, key)
                plain = decrypt_chunk(key, nonce, cipher)
                data = zstd.decompress(plain)
                if pos >= offset:
                    f_out.write(data)
                pos += 4 + clen
                tags.append(cipher[-TAG_SZ:])

    if _tree_mac(tags, key) != root_tag:
        raise ValueError("MAC mismatch")


def unpack_stream(
    src: Path,
    dst: Path,
    key: bytes,
    verify_only: bool = False,
    progress: bool = False,
    offset: int = 0,
) -> None:
    """Unpack *src* into *dst*, optionally starting at *offset* bytes."""

    with open(src, "rb") as f_in:
        header = bytearray()
        while not header.endswith(b"\n\n"):
            b = f_in.read(1)
            if not b:
                raise ValueError("truncated header")
            header.extend(b)
        meta = json.loads(header[:-2].decode("utf-8"))
        root_tag = bytes.fromhex(meta["root_tag"])
        chunk_count = meta["chunks"]
        tags: List[bytes] = []
        pos = len(header)
        out_fh = None if verify_only else open(dst, "wb")
        try:
            for cid in range(chunk_count):
                clen = int.from_bytes(_read_exact(f_in, 4), "big")
                cipher = _read_exact(f_in, clen)
                tags.append(cipher[-TAG_SZ:])
                nonce = _derive_nonce(cid, key)
                plain = decrypt_chunk(key, nonce, cipher)
                data = zstd.decompress(plain)
                if out_fh and pos >= offset:
                    out_fh.write(data)
                pos += 4 + clen
        finally:
            if out_fh:
                out_fh.close()
    if _tree_mac(tags, key) != root_tag:
        raise ValueError("MAC mismatch")
