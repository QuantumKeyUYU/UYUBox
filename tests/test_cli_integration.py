# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

from click.testing import CliRunner
from pathlib import Path

from zilant_prime_core.cli import cli


def test_cli_pack_and_unpack(tmp_path: Path):
    runner = CliRunner()

    # ── подготовка ──
    src = tmp_path / "song.txt"
    src.write_text("Born to be a dragon!")

    # ── pack (пароль + подтверждение) ──
    result = runner.invoke(
        cli,
        ["pack", str(src), "-p", "-"],
        input="s3cr3t\ns3cr3t\n",
    )
    assert result.exit_code == 0, result.stdout

    container = src.with_suffix(".zil")
    assert container.exists()

    # ── unpack (пароль) ──
    dest = tmp_path / "extracted"
    result = runner.invoke(
        cli,
        ["unpack", str(container), "-p", "-", "-d", str(dest)],
        input="s3cr3t\n",
    )
    assert result.exit_code == 0, result.stdout

    # файл должен быть song.txt
    extracted = dest / "song.txt"
    assert extracted.exists()
    assert extracted.read_text() == "Born to be a dragon!"
