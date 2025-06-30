# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from __future__ import annotations

import pytest
import secrets
from click.testing import CliRunner
from cryptography.exceptions import InvalidTag
from pathlib import Path
from threading import Thread

from container import get_metadata, get_open_attempts, unpack_file
from zilant_prime_core.cli import cli


def test_decoy_indistinguishable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = Path("sec.txt")
    src.write_text("secret")
    result = CliRunner().invoke(
        cli,
        ["pack", str(src), "-p", "x" * 32, "--fake-metadata", "--decoy", "1"],
    )
    assert result.exit_code == 0
    decoy = next(tmp_path.glob("decoy_*.zil"))
    real_meta = get_metadata(tmp_path / "sec.zil")
    decoy_meta = get_metadata(decoy)
    base_keys = {"magic", "version", "mode", "nonce_hex", "orig_size", "checksum_hex"}
    assert base_keys <= real_meta.keys()
    assert base_keys <= decoy_meta.keys()
    assert real_meta["magic"] == decoy_meta["magic"]
    assert real_meta["version"] == decoy_meta["version"]
    assert ("owner" in real_meta) and ("owner" not in decoy_meta)


def test_decoy_wrong_key_and_truncate(tmp_path):
    payload = Path(tmp_path / "d.txt")
    payload.write_text("data")
    from zilant_prime_core.utils.decoy import generate_decoy_files

    decoy = generate_decoy_files(tmp_path, 1)[0]
    with pytest.raises(InvalidTag):
        unpack_file(decoy, tmp_path / "out", b"y" * 32)
    truncated = decoy.read_bytes()[:-5]
    decoy.write_bytes(truncated)
    with pytest.raises(InvalidTag):
        unpack_file(decoy, tmp_path / "out2", b"y" * 32)


def test_decoy_parallel_attempts(tmp_path):
    from zilant_prime_core.utils.decoy import generate_decoy_files

    decoy = generate_decoy_files(tmp_path, 1)[0]

    def _try_unpack():
        with pytest.raises(InvalidTag):
            unpack_file(decoy, tmp_path / Path(f"o_{secrets.token_hex(2)}"), b"k" * 32)

    threads = [Thread(target=_try_unpack) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert get_open_attempts(decoy) == 5
