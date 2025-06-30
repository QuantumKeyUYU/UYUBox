# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
import time
from pathlib import Path

from zilant_prime_core.utils.anti_snapshot import TIMESTAMP_FILE, detect_snapshot, read_timestamp, write_timestamp


@pytest.fixture(autouse=True)
def clean_timestamp(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("zilant_prime_core.utils.anti_snapshot.TIMESTAMP_FILE", tmp_path / "ts.txt")
    yield


def test_write_and_read_timestamp():
    assert read_timestamp() is None
    write_timestamp(123.456)
    ts = read_timestamp()
    assert isinstance(ts, float)
    assert abs(ts - 123.456) < 1e-6


def test_read_timestamp_invalid():
    TIMESTAMP_FILE.write_text("bad")
    assert read_timestamp() is None


def test_detect_snapshot_first_run():
    assert detect_snapshot() is False
    assert TIMESTAMP_FILE.exists()


def test_detect_snapshot_within_threshold(monkeypatch):
    write_timestamp(1000.0)
    monkeypatch.setattr(time, "time", lambda: 1001.0)
    assert detect_snapshot() is False


def test_detect_snapshot_exceeds_threshold(monkeypatch):
    write_timestamp(1000.0)
    monkeypatch.setattr(time, "time", lambda: 2000.0)
    assert detect_snapshot() is True
