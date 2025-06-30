import os
import pytest
from click.testing import CliRunner

from zilant_prime_core.cli import cli
from zilant_prime_core.utils import pq_crypto


@pytest.mark.skipif(pq_crypto.kyber768 is None, reason="pqclean.kyber768 not installed")
def test_pq_genkey_kyber(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ["pq-genkeypair", "kyber768"])
        assert result.exit_code == 0
        assert os.path.exists("kyber768_pk.bin") and os.path.getsize("kyber768_pk.bin") > 0
        assert os.path.exists("kyber768_sk.bin") and os.path.getsize("kyber768_sk.bin") > 0


@pytest.mark.skipif(pq_crypto.dilithium2 is None, reason="pqclean.dilithium2 not installed")
def test_pq_genkey_dilithium(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ["pq-genkeypair", "dilithium2"])
        assert result.exit_code == 0
        assert os.path.exists("dilithium2_pk.bin") and os.path.getsize("dilithium2_pk.bin") > 0
        assert os.path.exists("dilithium2_sk.bin") and os.path.getsize("dilithium2_sk.bin") > 0
