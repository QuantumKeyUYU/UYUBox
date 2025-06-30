# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from click.testing import CliRunner

from zilant_prime_core.cli import cli


def test_unpack_dest_is_dir(tmp_path):
    # создаём контейнер с минимальным содержимым
    container = tmp_path / "a.zil"
    container.write_bytes(b"foo.bin\nhello")
    # создаём dest-директорию заранее
    dest = tmp_path / "dest_dir"
    dest.mkdir()
    result = CliRunner().invoke(cli, ["unpack", str(container), "--dest", str(dest), "-p", "qwe"])
    # должен быть abort — "Destination path already exists"
    assert "Destination path already exists" in result.output
    assert result.exit_code != 0


def test_pack_file_exists_confirm_prompt(tmp_path, monkeypatch):
    src = tmp_path / "foo.txt"
    src.write_text("ok")
    dest = tmp_path / "foo.zil"
    dest.write_bytes(b"old data")
    # monkeypatch confirm to return False, чтобы попали в _abort после confirm
    monkeypatch.setattr("click.confirm", lambda *a, **k: False)
    result = CliRunner().invoke(cli, ["pack", str(src), "-p", "123"])
    assert "already exists" in result.output
    assert "Aborted" in result.output
    assert result.exit_code != 0
