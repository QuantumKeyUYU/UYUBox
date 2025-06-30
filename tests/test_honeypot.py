# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from click.testing import CliRunner

from container import pack_file
from zilant_prime_core.cli import cli


def test_honeypot_mode(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "x.bin"
    src.write_text("data")
    key = b"k" * 32
    pack_file(src, tmp_path / "x.zil", key)
    sk = tmp_path / "dummy.sk"
    sk.write_bytes(b"0" * 32)
    result = CliRunner().invoke(
        cli,
        [
            "unpack",
            str(tmp_path / "x.zil"),
            "-p",
            "badbadbadbadbadbadbadbadbadbadbb",
            "--honeypot-test",
            "--pq-sk",
            str(sk),
        ],
    )
    assert result.exit_code == 0
    decoys = list(tmp_path.glob("decoy_*.zil"))
    assert decoys
    ledger = (tmp_path / "audit-ledger.jsonl").read_text().strip().splitlines()
    assert any("decoy_event" in line for line in ledger)
