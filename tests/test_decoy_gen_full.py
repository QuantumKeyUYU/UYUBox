# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import tempfile
import time
from pathlib import Path

import zilant_prime_core.decoy_gen as decoy_gen


def test_generate_decoy_file_creates_and_expires():
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td) / "test.zil"
        result = decoy_gen.generate_decoy_file(dest, size=32, expire_seconds=1)
        assert result.exists()
        stat = result.stat()
        assert abs(stat.st_size - 32) <= 1
        assert abs(stat.st_mtime - (time.time() + 1)) < 2
        time.sleep(1.1)
        removed = decoy_gen.sweep_expired_decoys(result.parent)
        assert removed == 1
        assert not result.exists()


def test_generate_decoy_files_batch_and_sweep():
    with tempfile.TemporaryDirectory() as td:
        dest_dir = Path(td)
        files = decoy_gen.generate_decoy_files(dest_dir, count=5, size=16, expire_seconds=1)
        assert len(files) == 5
        for f in files:
            assert f.exists()
        time.sleep(1.1)
        removed = decoy_gen.sweep_expired_decoys(dest_dir)
        assert removed == 5
        assert not list(dest_dir.glob("*.zil"))


def test_sweep_expired_decoys_handles_missing():
    with tempfile.TemporaryDirectory() as td:
        dest_dir = Path(td)
        _ = decoy_gen.generate_decoy_file(dest_dir / "1.zil", expire_seconds=0.5)
        file2 = decoy_gen.generate_decoy_file(dest_dir / "2.zil", expire_seconds=0.5)
        file2.unlink()
        time.sleep(0.6)
        removed = decoy_gen.sweep_expired_decoys(dest_dir)
        assert removed == 1


def test_generate_decoy_files_unique_names():
    with tempfile.TemporaryDirectory() as td:
        dest_dir = Path(td)
        files = decoy_gen.generate_decoy_files(dest_dir, count=20, size=8)
        names = {f.name for f in files}
        assert len(names) == len(files)


def test_sweep_expired_decoys_handles_file_disappear(monkeypatch):
    import os

    with tempfile.TemporaryDirectory() as td:
        dest_dir = Path(td)
        decoy_gen.generate_decoy_file(dest_dir / "boom.zil", expire_seconds=-1)

        def fake_stat(self):
            os.unlink(self)
            raise FileNotFoundError

        monkeypatch.setattr(Path, "stat", fake_stat)
        removed = decoy_gen.sweep_expired_decoys(dest_dir)
        assert removed == 0
