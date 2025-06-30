# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import time
from click.testing import CliRunner
from pathlib import Path

from zilant_prime_core.cli import cli
from zilant_prime_core.utils.decoy import generate_decoy_files, sweep_expired_decoys


def test_decoy_sweep_logging(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    files = generate_decoy_files(tmp_path, 5, expire_seconds=2)
    files[0].unlink()
    files[1].unlink()
    time.sleep(2.5)
    removed = sweep_expired_decoys(tmp_path)
    assert removed in (0, 3)
    ledger = Path("audit-ledger.jsonl").read_text()
    assert ledger.count("decoy_removed_early") >= 2
    assert ledger.count("decoy_purged") >= 3


def test_cli_decoy_sweep_option(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    generate_decoy_files(tmp_path, 1, expire_seconds=1)
    time.sleep(1.2)
    result = CliRunner().invoke(cli, ["--decoy-sweep", "--paranoid"])
    assert result.exit_code == 0
    assert "removed" in result.output
