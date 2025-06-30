# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
from click.testing import CliRunner

from zilant_prime_core.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_unpack_missing_password(tmp_path, runner):
    container = tmp_path / "cont.zil"
    container.write_bytes(b"file.bin\n" b"data")
    result = runner.invoke(cli, ["unpack", str(container)])
    assert result.exit_code != 0
    assert "Missing password" in result.output


def test_unpack_prompt_password(tmp_path, runner):
    container = tmp_path / "cont.zil"
    container.write_bytes(b"file.bin\n" b"data")
    result = runner.invoke(
        cli,
        ["unpack", str(container), "-p", "-"],
        input="pwd\n",
    )
    assert result.exit_code == 0
    out = tmp_path / "file.bin"
    assert out.exists()
