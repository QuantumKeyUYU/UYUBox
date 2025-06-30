# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

import zilant_prime_core.watchdog as wd


def test_hash_sources_and_zeroize(tmp_path, monkeypatch):
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text("print('1')")
    f2.write_text("print('2')")

    h = wd._hash_sources([f1, f2])
    assert h == wd._hash_sources([f1, f2])
    f2.write_text("changed")
    assert wd._hash_sources([f1, f2]) != h

    # prepare zeroize stubs
    monkeypatch.setattr("zilant_prime_core.utils.secure_logging.zeroize", lambda: None)
    monkeypatch.setattr("zilant_prime_core.notify.Notifier", lambda: type("N", (), {"notify": lambda self, m: None})())

    code = {}

    def fake_exit(c):
        code["c"] = c
        raise SystemExit(c)

    monkeypatch.setattr(wd.sys, "exit", fake_exit)
    with pytest.raises(SystemExit):
        wd._zeroize()
    assert code.get("c") == 134


def test_zeroize_handles_errors(monkeypatch):
    code = {}

    def fake_exit(c):
        code["c"] = c
        raise SystemExit(c)

    monkeypatch.setattr(wd.sys, "exit", fake_exit)
    monkeypatch.setattr(
        "zilant_prime_core.utils.secure_logging.zeroize",
        lambda: (_ for _ in ()).throw(RuntimeError()),
    )
    with pytest.raises(SystemExit):
        wd._zeroize()
    assert code.get("c") == 134
