# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_cli_negative_more.py

import pytest
from click.testing import CliRunner

from zilant_prime_core.cli import cli


@pytest.fixture
def sample_file(tmp_path):
    f = tmp_path / "file.bin"
    f.write_bytes(b"hello")
    return f


def test_pack_missing_password(sample_file):
    runner = CliRunner()
    # без -p/--password сразу Missing password
    result = runner.invoke(cli, ["pack", str(sample_file)])
    assert result.exit_code == 1
    assert "Missing password" in result.stdout


def test_pack_overwrite_prompt_decline(sample_file):
    runner = CliRunner()
    dest = sample_file.with_suffix(".zil")
    dest.write_bytes(b"")  # контейнер уже есть
    # respond "no" на подтверждение перезаписи
    result = runner.invoke(cli, ["pack", str(sample_file), "-p", "pw"], input="n\n")
    assert result.exit_code == 1
    assert "already exists" in result.stdout


def test_pack_overwrite_flag_false(sample_file):
    runner = CliRunner()
    # сначала упакуем
    runner.invoke(cli, ["pack", str(sample_file), "-p", "pw"])
    # затем без --overwrite
    result = runner.invoke(cli, ["pack", str(sample_file), "-p", "pw", "--no-overwrite"])
    assert result.exit_code == 1
    assert f"{sample_file.with_suffix('.zil').name} already exists" in result.stdout


def test_pack_overwrite_flag_true(sample_file):
    runner = CliRunner()
    runner.invoke(cli, ["pack", str(sample_file), "-p", "pw"])
    # с --overwrite перезаписываем без вопросов
    result = runner.invoke(cli, ["pack", str(sample_file), "-p", "pw", "--overwrite"])
    assert result.exit_code == 0
    assert sample_file.with_suffix(".zil").exists()


def test_unpack_missing_password(sample_file):
    runner = CliRunner()
    # запакуем, чтобы был файл .zil
    runner.invoke(cli, ["pack", str(sample_file), "-p", "pw"])
    container = sample_file.with_suffix(".zil")
    # не передали -p
    result = runner.invoke(cli, ["unpack", str(container), "-d", str(sample_file.parent / "out")])
    assert result.exit_code == 1
    assert "Missing password" in result.stdout


def test_unpack_file_exists_error(sample_file):
    runner = CliRunner()
    runner.invoke(cli, ["pack", str(sample_file), "-p", "pw"])
    container = sample_file.with_suffix(".zil")
    dest = sample_file.parent / "out"
    # первая распаковка
    runner.invoke(cli, ["unpack", str(container), "-p", "pw", "-d", str(dest)])
    # вторая — тот же путь => уже существует
    result = runner.invoke(cli, ["unpack", str(container), "-p", "pw", "-d", str(dest)])
    assert result.exit_code != 0
    # CLI выводит сообщение на русском
    assert "Destination path already exists" in result.stdout
