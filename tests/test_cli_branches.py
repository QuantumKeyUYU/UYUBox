# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_cli_branches.py

import os
from click.testing import CliRunner

from zilant_prime_core.cli import cli


def test_pack_missing_password_when_no_flag(tmp_path):
    # no -p means we should abort with "Missing password"
    src = tmp_path / "file.txt"
    src.write_text("hello")
    runner = CliRunner()
    result = runner.invoke(cli, ["pack", str(src)])
    assert result.exit_code != 0
    assert "Missing password" in result.stdout


def test_pack_existing_prompts_overwrite_then_abort(tmp_path):
    # existing .zil and no overwrite flag → prompt and abort
    src = tmp_path / "foo.txt"
    src.write_text("hi")
    zid = src.with_suffix(".zil")
    zid.write_bytes(b"")
    runner = CliRunner()
    # answer 'n' to overwrite?
    result = runner.invoke(cli, ["pack", str(src)], input="n\n")
    assert result.exit_code != 0
    assert "already exists" in result.stdout
    assert "Aborted" in result.stdout


def test_pack_no_overwrite_flag_false(tmp_path):
    # explicit --no-overwrite should abort right away
    src = tmp_path / "bar.txt"
    src.write_text("yo")
    dest = tmp_path / "custom.zil"
    dest.write_bytes(b"")
    runner = CliRunner()
    result = runner.invoke(cli, ["pack", str(src), "-p", "pw", "-o", str(dest), "--no-overwrite"])
    assert result.exit_code != 0
    assert f"{dest.name} already exists" in result.stdout


def test_unpack_missing_password(tmp_path):
    # unpack without -p must abort with "Missing password"
    cont = tmp_path / "d.zil"
    cont.write_bytes(os.urandom(32))
    runner = CliRunner()
    result = runner.invoke(cli, ["unpack", str(cont), "-d", str(tmp_path / "out")])
    assert result.exit_code != 0
    assert "Missing password" in result.stdout
