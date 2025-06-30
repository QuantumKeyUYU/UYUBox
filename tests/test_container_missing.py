# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

import src.aead
import src.container as container
import zilant_prime_core.utils.pq_crypto as pqcrypto


def test_unpack_blob_invalid_separator():
    with pytest.raises(ValueError):
        container.unpack(b"no-separator-here", b"x" * 32)


def test_pack_and_unpack_file_pq_mode(tmp_path, monkeypatch):
    # stub external pq_crypto
    class DummyKEM:
        def encapsulate(self, pk):
            return (b"KC", b"SH")

        def decapsulate(self, priv, kem_ct):
            return b"SH"

    def derive_key_pq(shared):
        return b"d" * 32

    monkeypatch.setattr(pqcrypto, "Kyber768KEM", DummyKEM)
    monkeypatch.setattr(pqcrypto, "derive_key_pq", derive_key_pq)

    # stub container.PQAEAD.encrypt to produce [kem_ct][nonce][plaintext]
    def fake_encrypt(pk, pt, aad=b""):
        nonce = b"N" * src.aead.PQAEAD._NONCE_LEN
        return b"KC" + nonce + pt

    monkeypatch.setattr(container.PQAEAD, "encrypt", staticmethod(fake_encrypt))

    # stub container.decrypt to simply return ciphertext
    monkeypatch.setattr(container, "decrypt", lambda key, nonce, ct, aad: ct)

    # prepare files
    src_file = tmp_path / "input.bin"
    data = b"HELLO"
    src_file.write_bytes(data)
    packed = tmp_path / "out.zil"
    dest = tmp_path / "dest.bin"
    key = b"x" * 32

    # pack in PQ mode and then unpack
    container.pack_file(src_file, packed, key, pq_public_key=b"pubkey")
    container.unpack_file(packed, dest, key, pq_private_key=b"privkey")

    # verify round-trip
    assert dest.read_bytes() == data
