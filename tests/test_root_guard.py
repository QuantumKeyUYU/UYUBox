import pytest

from zilant_prime_core.utils import root_guard


def test_is_device_rooted_when_checks_true(monkeypatch):
    monkeypatch.setattr(root_guard, "_check_uid_gid", lambda: True)
    assert root_guard.is_device_rooted()


def test_is_device_rooted_when_all_false(monkeypatch):
    monkeypatch.setattr(root_guard, "_check_uid_gid", lambda: False)
    monkeypatch.setattr(root_guard, "_check_root_binaries", lambda: False)
    monkeypatch.setattr(root_guard, "_check_mounts", lambda: False)
    monkeypatch.setattr(root_guard, "_check_selinux", lambda: False)
    monkeypatch.setattr(root_guard, "_check_ptrace", lambda: False)
    assert not root_guard.is_device_rooted()


def test_assert_safe_or_die_exits(monkeypatch):
    monkeypatch.setattr(root_guard, "is_device_rooted", lambda: True)
    monkeypatch.delenv("ZILANT_ALLOW_ROOT", raising=False)
    with pytest.raises(SystemExit):
        root_guard.assert_safe_or_die()


def test_ld_preload_detection(monkeypatch):
    monkeypatch.setenv("LD_PRELOAD", "/tmp/inject.so")
    assert root_guard.is_device_rooted()
