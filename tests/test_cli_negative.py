# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import os
from click.testing import CliRunner
from pathlib import Path

from zilant_prime_core.cli import cli


def test_cli_overwrite(tmp_path: Path):
    runner = CliRunner()
    data = tmp_path / "data.bin"
    data.write_bytes(os.urandom(64))

    # первый pack
    result1 = runner.invoke(cli, ["pack", str(data), "-p", "-"], input="pw\npw\n")
    assert result1.exit_code == 0

    # второй pack без --overwrite (должен упасть)
    result2 = runner.invoke(cli, ["pack", str(data), "-p", "-", "--no-overwrite"], input="pw\n")
    assert result2.exit_code != 0
