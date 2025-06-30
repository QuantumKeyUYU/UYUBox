# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
import zilant_prime_core.watchdog as wd


def test_watchdog_detects_change(tmp_path):
    mod = tmp_path / "m.py"
    mod.write_text("x=1")
    h = wd._hash_sources([mod])
    mod.write_text("x=2")
    assert wd._hash_sources([mod]) != h
