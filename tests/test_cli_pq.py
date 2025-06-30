import pytest
from click.testing import CliRunner

from zilant_prime_core.cli import cli
from zilant_prime_core.utils import pq_crypto


@pytest.mark.skipif(pq_crypto.kyber768 is None, reason="pqclean.kyber768 not installed")
def test_gen_kem_and_pack_unpack(tmp_path):
    runner = CliRunner()
    pk_path = tmp_path / "pk.bin"
    sk_path = tmp_path / "sk.bin"
    result = runner.invoke(cli, ["gen_kem_keys", "--out-pk", str(pk_path), "--out-sk", str(sk_path)])
    assert result.exit_code == 0
    src = tmp_path / "msg.txt"
    src.write_bytes(b"PQ CLI test")
    arc = tmp_path / "a.zil"
    result = runner.invoke(cli, ["pack", str(src), str(arc), "--pq-pub", str(pk_path), "-p", "pw"])
    assert result.exit_code == 0
    out = tmp_path / "out.txt"
    result = runner.invoke(cli, ["unpack", str(arc), str(out), "--pq-sk", str(sk_path), "-p", "pw"])
    assert result.exit_code == 0
    assert out.read_bytes() == b"PQ CLI test"
