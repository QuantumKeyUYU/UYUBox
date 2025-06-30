"""Проверяем генерацию и авто-очистку decoy-файлов с TTL."""

from __future__ import annotations

import time
from pathlib import Path

from zilant_prime_core.decoy_gen import generate_decoy_files, sweep_expired_decoys


def test_generate_and_sweep(tmp_path: Path) -> None:
    decoys_dir = tmp_path / "decoys"
    generate_decoy_files(decoys_dir, count=3, size=16, expire_seconds=0.1)
    assert len(list(decoys_dir.iterdir())) == 3

    time.sleep(0.15)  # ждём, пока TTL (0.1 с) истечёт
    removed = sweep_expired_decoys(decoys_dir)
    assert removed == 3
    assert not any(decoys_dir.iterdir())
