from click.testing import CliRunner
from pathlib import Path

import pqcrypto as pq
from zilant_prime_core.cli import cli


class DummyHybrid:
    def generate_keypair(self):
        return b"PKPQ", b"SKPQ", b"PKX", b"SKX"

    def encapsulate(self, pk):
        return b"CTPQ", None, b"EPK", None, b"SHARED"

    def decapsulate(self, sk, ct):
        assert ct == (b"CTPQ", b"EPK", b"")
        return b"SHARED"


class DummyAEAD:
    def __init__(self, key):
        pass

    def encrypt(self, nonce, pt, aad):
        return b"HDR" + pt[::-1]

    def decrypt(self, nonce, ct, aad):
        assert ct.startswith(b"HDR")
        return ct[3:][::-1]


def test_hpke_roundtrip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(pq, "HybridKEM", lambda: DummyHybrid())
    monkeypatch.setattr(pq, "ChaCha20Poly1305", DummyAEAD)

    def fake_encrypt(pk_tuple, data, aad=b""):
        kem = DummyHybrid()
        _hdr, _, _epk, _ek, _ = kem.encapsulate(pk_tuple)
        return b"HDR" + pk_tuple[0], b"cipher" + data

    def fake_decrypt(sk_tuple, hdr, ct, aad=b""):
        assert hdr.startswith(b"HDR")
        return ct[6:]

    monkeypatch.setattr(pq, "hybrid_encrypt", fake_encrypt)
    monkeypatch.setattr(pq, "hybrid_decrypt", fake_decrypt)

    kem = pq.HybridKEM()
    pk_pq, sk_pq, pk_x, sk_x = kem.generate_keypair()
    pq_pub = tmp_path / "pq.pk"
    pq_sk = tmp_path / "pq.sk"
    x_pub = tmp_path / "x.pk"
    x_sk = tmp_path / "x.sk"
    pq_pub.write_bytes(pk_pq)
    pq_sk.write_bytes(sk_pq)
    x_pub.write_bytes(pk_x)
    x_sk.write_bytes(sk_x)

    src = tmp_path / "plain.txt"
    src.write_bytes(b"hello")
    ct = tmp_path / "cipher.bin"
    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "hpke",
            "encrypt",
            str(src),
            str(ct),
            "--pq-pub",
            str(pq_pub),
            "--x-pub",
            str(x_pub),
        ],
    )
    assert res.exit_code == 0, res.output

    out = tmp_path / "out.txt"
    res = runner.invoke(
        cli,
        [
            "hpke",
            "decrypt",
            str(ct),
            str(out),
            "--pq-sk",
            str(pq_sk),
            "--x-sk",
            str(x_sk),
        ],
    )
    assert res.exit_code == 0, res.output
    assert out.read_bytes() == b"hello"
