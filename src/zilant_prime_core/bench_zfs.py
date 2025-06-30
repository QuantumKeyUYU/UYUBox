# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from zilant_prime_core.zilfs import ZilantFS


def bench_fs() -> float:
    """Write 100 MB through ZilantFS and return throughput (MB/s)."""
    key = b"k" * 32
    with TemporaryDirectory() as tmp:
        container = Path(tmp) / "bench.zil"
        fs = ZilantFS(container, key)
        path = fs.root / "dummy"
        start = time.time()
        with open(path, "wb") as fh:
            for _ in range(25):
                fh.write(b"\0" * 4 * 1024 * 1024)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except AttributeError:
                # fsync is missing only on exotic platforms
                pass
        fs.destroy("/")
        dur = time.time() - start
        mb_s = 100 / dur if dur else 0.0
        try:
            from prometheus_client import Gauge

            Gauge("zilfs_write_mb_per_s", "ZilantFS bench").set(mb_s)
        except Exception:
            pass
        return mb_s
