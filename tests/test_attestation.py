import json
from click.testing import CliRunner

from attestation import simulate_tpm_attestation
from zilant_prime_core.cli import cli


def test_simulate_tpm_attestation():
    res = simulate_tpm_attestation(b"data")
    assert "timestamp" in res and "hash" in res and "evidence" in res


def test_cli_attest_simulate(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"test")
    runner = CliRunner()
    out = runner.invoke(cli, ["attest", "simulate", "--in-file", str(f)])
    assert out.exit_code == 0
    j = json.loads(out.output)
    assert j["hash"] == simulate_tpm_attestation(b"test")["hash"]
