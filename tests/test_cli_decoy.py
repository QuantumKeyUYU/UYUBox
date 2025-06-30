# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from click.testing import CliRunner

from container import pack_file
from zilant_prime_core.cli import cli


def test_cli_pack_decoy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "data.bin"
    src.write_text("data")
    result = CliRunner().invoke(cli, ["pack", str(src), "-p", "pw", "--decoy", "2"])
    assert result.exit_code == 0
    decoys = list(tmp_path.glob("decoy_*.zil"))
    assert len(decoys) == 2
    assert (tmp_path / "data.zil").exists()


def test_cli_verify_integrity(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "f.txt"
    src.write_text("x")
    key = b"x" * 32
    pack_file(src, tmp_path / "f.zil", key)
    ok = CliRunner().invoke(cli, ["uyi", "verify-integrity", str(tmp_path / "f.zil")])
    assert ok.exit_code == 0
    assert "valid" in ok.output
    (tmp_path / "f.zil").write_bytes(b"bad")
    bad = CliRunner().invoke(cli, ["uyi", "verify-integrity", str(tmp_path / "f.zil")])
    assert bad.exit_code == 0
    assert "invalid" in bad.output
