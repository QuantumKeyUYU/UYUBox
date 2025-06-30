# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
from __future__ import annotations

import pytest
import time
from click.testing import CliRunner
from cryptography.exceptions import InvalidTag
from threading import Thread

from container import get_metadata, pack_file, unpack_file
from zilant_prime_core.cli import cli
from zilant_prime_core.utils.decoy import generate_decoy_files


def test_decoy_and_real_indistinguishable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "a.txt"
    src.write_text("x")
    key = b"k" * 32
    real = []
    for i in range(10):
        path = tmp_path / f"real_{i}.zil"
        pack_file(src, path, key)
        real.append(path)
    decoys = generate_decoy_files(tmp_path, 10)

    base_keys = set(get_metadata(real[0]).keys())
    base_msg = None
    for idx, p in enumerate(real + decoys):
        assert set(get_metadata(p).keys()) == base_keys
        with pytest.raises(InvalidTag) as exc:
            unpack_file(p, tmp_path / f"out_{idx}", b"b" * 32)
        msg = str(exc.value)
        if base_msg is None:
            base_msg = msg
        else:
            assert msg == base_msg


def test_decoy_expire_pack_option(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "b.txt"
    src.write_text("data")
    res = CliRunner().invoke(
        cli,
        ["pack", str(src), "-p", "pw", "--decoy", "1", "--decoy-expire", "1"],
    )
    assert res.exit_code == 0
    decoy = next(tmp_path.glob("decoy_*.zil"))
    assert decoy.exists()
    time.sleep(1.5)
    assert not decoy.exists()


def test_parallel_honeypot_decoys(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "c.txt"
    src.write_text("x")
    pack_file(src, tmp_path / "c.zil", b"k" * 32)
    sk = tmp_path / "d.sk"
    sk.write_bytes(b"0" * 32)

    def _attempt():
        CliRunner().invoke(
            cli,
            [
                "unpack",
                "c.zil",
                "-p",
                "bad",
                "--honeypot-test",
                "--pq-sk",
                str(sk),
                "--decoy-expire",
                "1",
            ],
        )

    threads = [Thread(target=_attempt) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    decoys = list(tmp_path.glob("decoy_*.zil"))
    assert len(decoys) == 5
    time.sleep(1.5)
    assert not any(p.exists() for p in decoys)
