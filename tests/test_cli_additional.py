# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_cli_additional.py
from click.testing import CliRunner

from zilant_prime_core.cli import cli  # :contentReference[oaicite:1]{index=1}

runner = CliRunner()


def test_pack_missing_password(tmp_path, monkeypatch):
    src = tmp_path / "foo.txt"
    src.write_text("data")
    result = runner.invoke(cli, ["pack", str(src)])
    assert "Missing password" in result.output
    assert result.exit_code != 0


def test_pack_file_exists_no_overwrite(tmp_path, monkeypatch):
    src = tmp_path / "foo.txt"
    src.write_text("x")
    dest = src.with_suffix(".zil")
    dest.write_bytes(b"")
    # simulate user saying "no" to overwrite
    monkeypatch.setattr("click.confirm", lambda *args, **kwargs: False)
    result = runner.invoke(cli, ["pack", str(src), "-p", "pw"])
    assert "already exists" in result.output
    assert result.exit_code != 0


def test_unpack_missing_password(tmp_path, monkeypatch):
    # create a dummy container
    cont = tmp_path / "c.zil"
    cont.write_bytes(b"hdr\npayload")
    tmp_path / "out"
    # none exists yet
    result = runner.invoke(cli, ["unpack", str(cont)])
    assert "Missing password" in result.output
    assert result.exit_code != 0


def test_unpack_dest_exists(tmp_path, monkeypatch):
    cont = tmp_path / "c.zil"
    cont.write_bytes(b"hdr\np")
    outdir = tmp_path / "out"
    outdir.mkdir()
    result = runner.invoke(cli, ["unpack", str(cont), "-p", "pw", "-d", str(outdir)])
    assert "already exists" in result.output
    assert result.exit_code != 0
