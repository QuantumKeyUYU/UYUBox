import os
from pathlib import Path

from aead import decrypt, encrypt
from crypto_core import hash_sha3
from kdf import derive_key
from shard_secret import recover_secret, split_secret
from utils.entropy import get_random_bytes
from utils.file_utils import atomic_write, secure_delete
from utils.secure_memory import wipe_bytes


def test_hash_sha3():
    assert hash_sha3(b"") == bytes.fromhex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")


def test_shard_secret_roundtrip():
    secret = b"secret-data"
    shards = split_secret(secret, parts=3)
    assert recover_secret(shards) == secret


def test_aead_encrypt_decrypt():
    key = os.urandom(32)
    nonce, ct = encrypt(key, b"data")
    pt = decrypt(key, nonce, ct)
    assert pt == b"data"


def test_kdf_length():
    key = derive_key(b"pwd", b"\x00" * 16)
    assert len(key) == 32


def test_wipe_bytes():
    buf = bytearray(b"secret")
    wipe_bytes(buf)
    assert buf == b"\x00" * 6


def test_entropy_unique():
    assert get_random_bytes(16) != get_random_bytes(16)


def test_file_utils(tmp_path: Path):
    p = tmp_path / "data.bin"
    atomic_write(p, b"abc")
    assert p.read_bytes() == b"abc"
    secure_delete(p)
    assert not p.exists()
