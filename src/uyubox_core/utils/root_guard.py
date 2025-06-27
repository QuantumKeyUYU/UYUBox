# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
"""Simple root / jailbreak detection helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterable

__all__ = ["is_device_rooted", "assert_safe_or_die", "harden_linux"]

_ROOT_INDICATORS: Iterable[str] = (
    "/system/xbin/su",
    "/system/bin/su",
    "/system/app/Superuser.apk",
    "/sbin/su",
    "/system/bin/.ext/.su",
    "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/data/local/su",
    "/su/bin/su",
    "/magisk",
)


def _check_ld_preload() -> bool:  # pragma: no cover
    return bool(os.environ.get("LD_PRELOAD"))


def _check_uid_gid() -> bool:  # pragma: no cover
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0 or getattr(os, "getegid", lambda: 1)() == 0
    return False


def _check_root_binaries() -> bool:  # pragma: no cover
    for p in _ROOT_INDICATORS:
        if Path(p).exists():
            return True
    return False


def _check_mounts() -> bool:  # pragma: no cover
    try:
        with open("/proc/self/mountinfo", "r") as fh:
            for line in fh:
                if " rw," in line.split()[-1]:
                    if "/" in line.split()[4]:
                        return False
    except OSError:
        # failed to read mountinfo; assume not rooted
        return False
    return False


def _check_selinux() -> bool:  # pragma: no cover
    path = Path("/sys/fs/selinux/enforce")
    try:
        if path.exists() and path.read_text().strip() != "1":
            return True
    except OSError:
        # unable to read SELinux status
        return False
    return False


def _check_ptrace() -> bool:  # pragma: no cover
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith("TracerPid:"):
                    pid = int(line.split()[1])
                    return pid != 0
    except OSError:
        # cannot read /proc/self/status
        return False
    return False


def _check_hooking() -> bool:  # pragma: no cover
    """Detect common hooking frameworks like Frida."""
    try:
        with open("/proc/self/maps", "r") as fh:
            content = fh.read().lower()
            for marker in ("frida", "xposed", "substrate"):
                if marker in content:
                    return True
    except OSError:
        # reading /proc/self/maps failed
        return False
    return "FRIDA" in os.environ


def is_device_rooted() -> bool:
    """Return True if current environment appears to be rooted/jailbroken."""
    if _check_uid_gid():
        return True
    if _check_root_binaries():
        return True
    if _check_mounts():
        return True
    if _check_selinux():
        return True
    if _check_ptrace():
        return True
    if _check_ld_preload():
        return True
    if _check_hooking():
        return True
    return False


def assert_safe_or_die() -> None:
    """Exit the process if running on a rooted device."""
    if is_device_rooted():
        sys.stderr.write("Root environment detected. Aborting.\n")
        sys.stderr.flush()
        sys.exit(99)


def harden_linux() -> None:
    """Apply minimal seccomp and capability restrictions (best-effort)."""
    try:  # pragma: no cover - optional
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c"))

        # drop ptrace and module loading caps if possible
        PR_CAPBSET_DROP = 24
        CAP_SYS_PTRACE = 19
        CAP_SYS_MODULE = 16
        for cap in (CAP_SYS_PTRACE, CAP_SYS_MODULE):
            libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)

        # very small seccomp filter: allow read/write/exit only
        try:
            import seccomp

            f = seccomp.SyscallFilter(defaction=seccomp.SCMP_ACT_KILL)
            for sc in ("read", "write", "exit", "exit_group"):
                try:
                    f.add_rule(seccomp.SCMP_ACT_ALLOW, sc)
                except Exception:
                    # rule may not exist on this kernel
                    pass
            f.load()
        except Exception:
            # seccomp not available; continue without it
            pass
        # landlock restrict filesystem access if library available
        try:
            import landlock  # type: ignore

            ruleset = landlock.LandlockRuleset(handled_access_fs=set(landlock.AccessFS))
            ruleset.create()
            ruleset.restrict_self()
        except Exception:
            # landlock unavailable; ignore
            pass
    except Exception:
        # hardening failed unexpectedly
        pass
