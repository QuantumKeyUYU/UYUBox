# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT


from click.testing import CliRunner

import zilant_prime_core.cli as cli_mod
from zilant_prime_core.container.metadata import MetadataError

runner = CliRunner()


def test_pack_no_overwrite_abort(tmp_path):
    src = tmp_path / "x.txt"
    src.write_text("X")
    dest = src.with_suffix(".zil")
    dest.write_bytes(b"")  # уже есть
    result = runner.invoke(cli_mod.cli, ["pack", str(src), "-p", "pw", "--no-overwrite"])
    assert result.exit_code == 1
    assert "already exists" in result.output


def test_pack_missing_password(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("A")
    result = runner.invoke(cli_mod.cli, ["pack", str(src)])
    assert result.exit_code == 1
    assert "Missing password" in result.output


def test_pack_metadata_error(tmp_path, monkeypatch):
    src = tmp_path / "a.txt"
    src.write_text("A")
    monkeypatch.setattr(cli_mod, "_pack_bytes", lambda *args, **kw: (_ for _ in ()).throw(MetadataError("bad")))
    result = runner.invoke(cli_mod.cli, ["pack", str(src), "-p", "pw"])
    assert result.exit_code == 1
    assert "bad" in result.output


def test_unpack_dest_exists(tmp_path):
    arc = tmp_path / "z.zil"
    arc.write_bytes(b"X")
    out = tmp_path / "out"
    out.mkdir()
    result = runner.invoke(cli_mod.cli, ["unpack", str(arc), "-p", "pw", "-d", str(out)])
    assert result.exit_code == 1
    assert "Destination path already exists" in result.output


def test_unpack_missing_password(tmp_path):
    arc = tmp_path / "z.zil"
    arc.write_bytes(b"\n")
    result = runner.invoke(cli_mod.cli, ["unpack", str(arc), "-d", str(tmp_path / "o")])
    assert result.exit_code == 1
    assert "Missing password" in result.output


def test_unpack_unpack_error(monkeypatch, tmp_path):
    arc = tmp_path / "z.zil"
    arc.write_bytes(b"\n")
    monkeypatch.setattr(cli_mod, "_unpack_bytes", lambda *a, **k: (_ for _ in ()).throw(Exception("oops")))
    result = runner.invoke(cli_mod.cli, ["unpack", str(arc), "-p", "pw", "-d", str(tmp_path / "o")])
    assert result.exit_code == 1
    assert "Unpack error" in result.output
