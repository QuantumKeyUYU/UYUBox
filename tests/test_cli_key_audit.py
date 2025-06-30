import hashlib
from click.testing import CliRunner

from key_lifecycle import AuditLog
from zilant_prime_core.cli import cli


def test_cli_key_rotate(tmp_path):
    in_key = tmp_path / "old.key"
    out_key = tmp_path / "new.key"
    old = b"o" * 32
    in_key.write_bytes(old)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output",
            "json",
            "key",
            "rotate",
            "--days",
            "2",
            "--in-key",
            str(in_key),
            "--out-key",
            str(out_key),
        ],
    )
    assert result.exit_code == 0
    expected = hashlib.blake2s((2).to_bytes(4, "big"), key=old).digest()
    assert out_key.read_bytes() == expected
    assert out_key.name in result.output


def test_cli_audit_verify(tmp_path, monkeypatch):
    log = AuditLog(path=tmp_path / "audit.log")
    log.append_event("E1")
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    res_ok = runner.invoke(cli, ["--output", "json", "audit", "verify"])
    assert res_ok.exit_code == 0
    assert "valid" in res_ok.output
    (tmp_path / "audit.log").write_text("corrupt\n")
    res_bad = runner.invoke(cli, ["--output", "json", "audit", "verify"])
    assert res_bad.exit_code != 0
