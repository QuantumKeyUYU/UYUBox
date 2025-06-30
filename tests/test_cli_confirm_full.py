# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import click
from click.testing import CliRunner

from zilant_prime_core.cli import cli


def test_pack_confirm_abort(tmp_path, monkeypatch):
    src = tmp_path / "file.txt"
    src.write_text("data")
    dest = tmp_path / "file.zil"
    dest.write_bytes(b"xxx")

    # Подменяем click.confirm: всегда False — "n"
    monkeypatch.setattr(click, "confirm", lambda *a, **k: False)
    result = CliRunner().invoke(cli, ["pack", str(src), "-p", "pw"])
    assert "already exists" in result.output
    assert "Aborted" in result.output
    assert result.exit_code != 0


def test_unpack_dest_dir_confirm_abort(tmp_path, monkeypatch):
    container = tmp_path / "foo.zil"
    container.write_bytes(b"file.bin\nhello")
    out_file = tmp_path / "file.bin"
    out_file.write_bytes(b"olddata")

    # Подменяем click.confirm: всегда False — "n"
    monkeypatch.setattr(click, "confirm", lambda *a, **k: False)
    result = CliRunner().invoke(
        cli,
        ["unpack", str(container), "-p", "pw", "--dest", str(tmp_path)],
    )
    # Если файл уже есть, команда должна abort'иться
    assert "already exists" in result.output
    assert "Aborted" in result.output
    assert result.exit_code != 0


def test_unpack_dest_path_is_dir(tmp_path):
    container = tmp_path / "foo.zil"
    container.write_bytes(b"file.bin\nhello")
    # Создаём ПАПКУ вместо файла
    out_dir = tmp_path / "file.bin"
    out_dir.mkdir()
    result = CliRunner().invoke(
        cli,
        ["unpack", str(container), "-p", "pw", "--dest", str(tmp_path)],
    )
    # cli должен abort'иться с ошибкой "Destination path already exists"
    assert "already exists" in result.output
    assert "Aborted" in result.output
    assert result.exit_code != 0
