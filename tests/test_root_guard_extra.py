# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import builtins

import zilant_prime_core.utils.root_guard as rg

original_open = builtins.open


def test_all_root_checks(monkeypatch):
    monkeypatch.setattr(rg, "_check_uid_gid", lambda: True)
    monkeypatch.setattr(rg, "_check_root_binaries", lambda: False)
    monkeypatch.setattr(rg, "_check_mounts", lambda: False)
    monkeypatch.setattr(rg, "_check_selinux", lambda: False)
    monkeypatch.setattr(rg, "_check_ptrace", lambda: False)
    monkeypatch.setattr(rg, "_check_ld_preload", lambda: False)
    assert rg.is_device_rooted() is True

    monkeypatch.setattr(rg, "_check_uid_gid", lambda: False)
    monkeypatch.setattr(rg, "_check_root_binaries", lambda: True)
    assert rg.is_device_rooted() is True

    monkeypatch.setattr(rg, "_check_root_binaries", lambda: False)
    monkeypatch.setattr(rg, "_check_mounts", lambda: True)
    assert rg.is_device_rooted() is True

    monkeypatch.setattr(rg, "_check_mounts", lambda: False)
    monkeypatch.setattr(rg, "_check_selinux", lambda: True)
    assert rg.is_device_rooted() is True

    monkeypatch.setattr(rg, "_check_selinux", lambda: False)
    monkeypatch.setattr(rg, "_check_ptrace", lambda: True)
    assert rg.is_device_rooted() is True

    monkeypatch.setattr(rg, "_check_ptrace", lambda: False)
    monkeypatch.setattr(rg, "_check_ld_preload", lambda: True)
    assert rg.is_device_rooted() is True

    # Всё False — безопасно
    monkeypatch.setattr(rg, "_check_ld_preload", lambda: False)
    assert rg.is_device_rooted() is False


def test_hooking_detection(monkeypatch):
    def fake_open(path: str, mode: str = "r", *args, **kwargs):
        if path == "/proc/self/maps":
            import io

            return io.StringIO("/usr/lib/frida.so")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    assert rg.is_device_rooted() is True
