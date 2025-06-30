# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors


import pytest
from click.testing import CliRunner

from zilant_prime_core.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_pack_prompt_password(tmp_path, runner):
    src = tmp_path / "foo.txt"
    src.write_text("hello")
    # Если передаём "-p -", Runner спросит пароль дважды
    result = runner.invoke(
        cli,
        ["pack", str(src), "-p", "-"],
        input="secret\nsecret\n",
    )
    assert result.exit_code == 0
    out_file = tmp_path / "foo.zil"
    assert out_file.exists()


def test_pack_overwrite_decline(tmp_path, runner):
    src = tmp_path / "foo.txt"
    src.write_text("data")
    dest = tmp_path / "foo.zil"
    dest.write_bytes(b"old")
    # Ответ "n" на overwrite
    result = runner.invoke(
        cli,
        ["pack", str(src), "-o", str(dest), "-p", "pwd"],
        input="n\n",
    )
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_pack_overwrite_accept(tmp_path, runner):
    src = tmp_path / "foo.txt"
    src.write_text("data")
    dest = tmp_path / "foo.zil"
    dest.write_bytes(b"old")
    # Ответ "y" на overwrite
    result = runner.invoke(
        cli,
        ["pack", str(src), "-o", str(dest), "-p", "pwd"],
        input="y\n",
    )
    assert result.exit_code == 0
    # Проверяем, что файл перезаписан (размер изменился)
    assert dest.read_bytes() != b"old"


def test_unpack_too_small(tmp_path, runner):
    small = tmp_path / "small.zil"
    small.write_bytes(b"abc")  # меньше, чем нужно
    result = runner.invoke(
        cli,
        ["unpack", str(small), "-p", "pwd"],
    )
    assert result.exit_code != 0
    assert "Container too small" in result.output


def test_unpack_dest_exists(tmp_path, runner):
    # Создаём валидный контейнер: имя + "\n" + payload
    container = tmp_path / "bar.zil"
    container.write_bytes(b"file.bin\ndata")
    out_file = tmp_path / "file.bin"
    out_file.write_bytes(b"old")
    # Задаём параметр --dest, когда out уже существует
    result = runner.invoke(
        cli,
        ["unpack", str(container), "-d", str(tmp_path), "-p", "pwd"],
    )
    assert result.exit_code != 0
    assert "already exists" in result.output
