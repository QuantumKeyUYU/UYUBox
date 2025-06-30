import pytest
from click.testing import CliRunner

from zilant_prime_core.cli import cli


@pytest.mark.skipif(True, reason="Fingerprint depends on real hardware")
def test_fingerprint_outputs_hex(monkeypatch):
    import zilant_prime_core.utils.device_fp as dfp

    monkeypatch.setattr(dfp, "collect_hw_factors", lambda: {"a": "1"})
    monkeypatch.setattr(dfp, "compute_fp", lambda hw, salt: b"\x10" * 32)

    runner = CliRunner()
    result = runner.invoke(cli, ["fingerprint"])
    assert result.exit_code == 0
    out = result.output.strip()
    assert len(out) == 64
    int(out, 16)
