import json
import os
import pytest
import sys
import types
from pathlib import Path

import streaming_aead


def _corrupt_root_tag(file_path: Path) -> None:
    """
    Заменяет в JSON-заголовке поля root_tag на нули той же длины.
    Не трогает остальную часть файла, чтобы не ломать чтение.
    """
    raw = bytearray(file_path.read_bytes())
    sep = raw.find(b"\n\n")
    if sep < 0:
        raise ValueError("No header found")
    hdr = raw[:sep].decode("utf-8")
    meta = json.loads(hdr)
    old_tag = meta.get("root_tag", "")
    # подменяем рутовый MAC на ноль той же длины (в hex-символах)
    meta["root_tag"] = "0" * len(old_tag)
    new_hdr = json.dumps(meta).encode("utf-8") + b"\n\n"
    file_path.write_bytes(new_hdr + raw[sep + 2 :])


def test__read_exact_with_retry(monkeypatch):
    class FakeFH:
        def __init__(self):
            self.called = False

        def read(self, n: int) -> bytes:
            if not self.called:
                self.called = True
                return b""
            return b"HELLO"

    fake = FakeFH()
    # Убираем реальный sleep, чтобы тест шел мгновенно
    monkeypatch.setattr(streaming_aead.time, "sleep", lambda _: None)
    out = streaming_aead._read_exact(fake, 5)
    assert out == b"HELLO"


def test_insufficient_data_resume(tmp_path):
    small = tmp_path / "small.bin"
    small.write_bytes(b"xx")
    with pytest.raises(ValueError, match="insufficient data for resume"):
        streaming_aead.resume_decrypt(
            path=small,
            key=b"\0" * 32,
            have_bytes=1,
            out_path=tmp_path / "out.bin",
        )


def test_truncated_header_unpack(tmp_path):
    src = tmp_path / "nohdr.bin"
    src.write_bytes(b"this is not a header")
    with pytest.raises(ValueError, match="truncated header"):
        streaming_aead.unpack_stream(
            src=src,
            dst=tmp_path / "out.bin",
            key=b"\0" * 32,
        )


def test_pack_unpack_roundtrip(tmp_path):
    data = b"abc123" * 1000
    src = tmp_path / "data.bin"
    src.write_bytes(data)

    key = os.urandom(32)
    packed = tmp_path / "data.zst"
    streaming_aead.pack_stream(src, packed, key)

    out = tmp_path / "data.out"
    streaming_aead.unpack_stream(packed, out, key)
    assert out.read_bytes() == data


def test_resume_full_data(tmp_path):
    data = b"0123456789" * 500
    src = tmp_path / "full.bin"
    src.write_bytes(data)

    key = os.urandom(32)
    packed = tmp_path / "full.zst"
    streaming_aead.pack_stream(src, packed, key)
    total = packed.stat().st_size

    out = tmp_path / "full.out"
    streaming_aead.resume_decrypt(
        path=packed,
        key=key,
        have_bytes=total,
        out_path=out,
        offset=0,
    )
    assert out.read_bytes() == data


def test_resume_no_data_at_full_offset(tmp_path):
    data = b"foobar" * 200
    src = tmp_path / "foo.bin"
    src.write_bytes(data)

    key = os.urandom(32)
    packed = tmp_path / "foo.zst"
    streaming_aead.pack_stream(src, packed, key)
    total = packed.stat().st_size

    out = tmp_path / "empty.out"
    streaming_aead.resume_decrypt(
        path=packed,
        key=key,
        have_bytes=total,
        out_path=out,
        offset=total,
    )
    assert out.exists()
    assert out.read_bytes() == b""


def test_invalid_mac_resume_decrypt(tmp_path):
    data = b"rename me" * 300
    src = tmp_path / "in.bin"
    src.write_bytes(data)

    key = b"\x02" * 32
    packed = tmp_path / "in.zst"
    streaming_aead.pack_stream(src, packed, key)
    _corrupt_root_tag(packed)

    with pytest.raises(ValueError, match="MAC mismatch"):
        streaming_aead.resume_decrypt(
            path=packed,
            key=key,
            have_bytes=packed.stat().st_size,
            out_path=tmp_path / "out_fail.bin",
        )


def test_invalid_mac_unpack_stream(tmp_path):
    data = b"something else" * 200
    src = tmp_path / "in2.bin"
    src.write_bytes(data)

    key = b"\x03" * 32
    packed = tmp_path / "in2.zst"
    streaming_aead.pack_stream(src, packed, key)
    _corrupt_root_tag(packed)

    with pytest.raises(ValueError, match="MAC mismatch"):
        streaming_aead.unpack_stream(
            src=packed,
            dst=tmp_path / "out2_fail.bin",
            key=key,
        )


def test_encrypt_decrypt_chunk_fallback(monkeypatch):
    # Падение в fallback-ветку, когда _NativeAEAD = None
    monkeypatch.setattr(streaming_aead, "_NativeAEAD", None)

    # Эмулируем модуль nacl.bindings
    fake = types.ModuleType("nacl.bindings")
    fake.crypto_aead_xchacha20poly1305_ietf_encrypt = lambda data, aad, nonce, key: b"CT" + data
    fake.crypto_aead_xchacha20poly1305_ietf_decrypt = lambda ct, aad, nonce, key: ct[2:]
    sys.modules["nacl.bindings"] = fake

    key = b"\x00" * 32
    nonce = b"\x01" * streaming_aead.NONCE_SZ
    data = b"hello fallback"
    aad = b"AAD"

    ct = streaming_aead.encrypt_chunk(key, nonce, data, aad=aad)
    assert ct == b"CT" + data

    pt = streaming_aead.decrypt_chunk(key, nonce, ct, aad=aad)
    assert pt == data


def test_encrypt_decrypt_chunk_native(monkeypatch):
    # Ветка _NativeAEAD != None
    class DummyNative:
        def __init__(self, key):
            self._k = key

        def encrypt(self, nonce, data, aad):
            return b"N" + nonce + aad + data

        def decrypt(self, nonce, cipher, aad):
            prefix = b"N" + nonce + aad
            assert cipher.startswith(prefix)
            return cipher[len(prefix) :]

    monkeypatch.setattr(streaming_aead, "_NativeAEAD", DummyNative)

    key = b"\x10" * 32
    nonce = b"\x02" * streaming_aead.NONCE_SZ
    data = b"hello native"
    aad = b"ZZ"

    ct = streaming_aead.encrypt_chunk(key, nonce, data, aad=aad)
    assert ct == b"N" + nonce + aad + data

    pt = streaming_aead.decrypt_chunk(key, nonce, ct, aad=aad)
    assert pt == data
