# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os

from crypto_core import hash_sha3
from zilant_prime_core.utils.device_fp_fallback import device_fp_fallback


def test_cpuinfo_fingerprint(tmp_path):
    info = tmp_path / "cpuinfo"
    info.write_text("hello cpu")
    fp = device_fp_fallback(str(info))
    assert fp == hash_sha3(b"hello cpu", hex_output=True)


def test_fallback_on_ioerror(monkeypatch):
    monkeypatch.setattr("pathlib.Path.read_bytes", lambda self: (_ for _ in ()).throw(OSError()))
    fp = device_fp_fallback("/nonexistent")
    assert isinstance(fp, str) and len(fp) >= 16


def test_monotonic_ns_control(monkeypatch):
    monkeypatch.setattr(os, "path", os.path)  # ensure os imported
    monkeypatch.setattr("time.monotonic_ns", lambda: 123456789)
    monkeypatch.setattr("pathlib.Path.read_bytes", lambda self: (_ for _ in ()).throw(OSError()))
    fp = device_fp_fallback("/none")
    expected = hash_sha3(str(123456789).encode(), hex_output=True)
    assert fp == expected
