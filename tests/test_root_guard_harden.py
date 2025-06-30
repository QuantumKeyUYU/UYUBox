import ctypes
import ctypes.util
import sys
import types

import zilant_prime_core.utils.root_guard as rg


def test_harden_linux_invokes_prctl_and_seccomp(monkeypatch):
    calls = []

    class FakeLibc:
        def prctl(self, option, cap, arg3, arg4, arg5):
            calls.append(("prctl", option, cap))

    monkeypatch.setattr(ctypes.util, "find_library", lambda name: "libc.so")
    monkeypatch.setattr(ctypes, "CDLL", lambda name: FakeLibc())

    fake_filter = types.SimpleNamespace(
        add_rule=lambda act, sc: calls.append(("rule", sc)),
        load=lambda: calls.append(("load",)),
    )
    fake_seccomp = types.SimpleNamespace(
        SCMP_ACT_KILL=0,
        SCMP_ACT_ALLOW=1,
        SyscallFilter=lambda *a, **kw: fake_filter,
    )
    monkeypatch.setitem(sys.modules, "seccomp", fake_seccomp)

    fake_ruleset = types.SimpleNamespace(
        create=lambda: calls.append(("create",)),
        restrict_self=lambda: calls.append(("restrict_self",)),
    )
    fake_landlock = types.SimpleNamespace(
        LandlockRuleset=lambda handled_access_fs: fake_ruleset,
        AccessFS={"read", "write"},
    )
    monkeypatch.setitem(sys.modules, "landlock", fake_landlock)

    rg.harden_linux()

    assert ("prctl", 24, 19) in calls
    assert ("load",) in calls
    assert ("restrict_self",) in calls
