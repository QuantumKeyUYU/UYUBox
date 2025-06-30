# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
import os
import pytest
import tempfile
import types

from zilant_prime_core.utils import hash_challenge, honeyfile
from zilant_prime_core.utils import root_guard as rg
from zilant_prime_core.utils import screen_guard


def test_honeyfile_detection():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "bait.txt")
        honeyfile.create_honeyfile(p)
        assert honeyfile.is_honeyfile(p)


def test_hash_challenge_cache():
    with tempfile.NamedTemporaryFile("wb", delete=False) as fh:
        fh.write(b"x")
        fh.flush()
        a = hash_challenge.hash_challenge(fh.name)
        b = hash_challenge.hash_challenge(fh.name)
        assert a == b
    os.remove(fh.name)


def test_root_guard_full(monkeypatch):
    monkeypatch.setattr(rg, "_check_uid_gid", lambda: True)
    for fn in ("_check_root_binaries", "_check_mounts", "_check_selinux", "_check_ptrace", "_check_ld_preload"):
        monkeypatch.setattr(rg, fn, lambda: False)
    assert rg.is_device_rooted()
    monkeypatch.setattr(rg, "is_device_rooted", lambda: True)
    with pytest.raises(SystemExit):
        rg.assert_safe_or_die()


def test_screen_guard_process():
    sg_class = screen_guard.ScreenGuard
    guard = sg_class()
    guard._iter_proc_names = types.MethodType(lambda self: ["obs.exe"], guard)
    with pytest.raises(screen_guard.ScreenGuardError):
        guard.assert_secure()
