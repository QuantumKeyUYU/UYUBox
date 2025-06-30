# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_cli_overwrite_flags.py

from click.testing import CliRunner

from zilant_prime_core.cli import main as cli_main


def write_dummy(path, data=b""):
    with open(path, "wb") as f:
        f.write(data)


def test_pack_and_unpack_overwrite_flag(tmp_path, monkeypatch):
    # Создаём входной файл
    inp = tmp_path / "in.bin"
    write_dummy(inp, b"HELLO")

    # Пакуем первый раз
    runner = CliRunner()
    result1 = runner.invoke(cli_main, ["pack", "-p", "pass", str(inp)])
    assert result1.exit_code == 0

    # Пытаемся запаковать в тот же файл без --overwrite → ошибка
    result2 = runner.invoke(cli_main, ["pack", "-p", "pass", str(inp)])
    assert result2.exit_code != 0
    assert "already exists" in result2.output

    # С флагом --overwrite должно быть ок
    result3 = runner.invoke(cli_main, ["pack", "-p", "pass", "--overwrite", str(inp)])
    assert result3.exit_code == 0
