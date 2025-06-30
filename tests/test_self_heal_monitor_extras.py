# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

import zilant_prime_core.self_heal.monitor as mon_mod
from zilant_prime_core.self_heal.monitor import _Handler


@pytest.fixture(autouse=True)
def clear_env(monkeypatch, tmp_path):
    # ensure no self-destruct happens unless explicitly set
    monkeypatch.delenv("ZILANT_SELF_DESTRUCT", raising=False)
    (tmp_path / "watch.me").write_text("data")
    yield


def test_handler_swallows_exceptions_and_logs(monkeypatch, tmp_path):
    """
    If any of the rotate/record/prove/destruct calls throws,
    on_modified should NOT propagate but record a failure event.
    """
    path = tmp_path / "watch.me"
    handler = _Handler(path)

    # make rotate_key throw
    monkeypatch.setattr(mon_mod, "rotate_key", lambda k: (_ for _ in ()).throw(Exception("boom")))
    recorded = []
    # intercept record_event
    monkeypatch.setattr(mon_mod, "record_event", lambda info: recorded.append(info))
    # others no-op
    monkeypatch.setattr(mon_mod, "prove_intact", lambda digest: None)
    monkeypatch.setattr(mon_mod, "maybe_self_destruct", lambda p: None)

    class Evt:
        src_path = str(path)

    # this should *not* raise
    handler.on_modified(Evt())
    # we should have a single record_event with failure info
    assert recorded, "Expected record_event to be called"
    evt = recorded[-1]
    assert evt.get("event") == "self_heal_handler_failed"
    assert str(path) in evt.get("file", "")


def test_handler_ignores_other_paths(monkeypatch, tmp_path):
    """
    Events for unrelated src_path should be ignored (no exceptions, no calls).
    """
    path = tmp_path / "watch.me"
    handler = _Handler(path)
    # intercept record_event
    calls = []
    monkeypatch.setattr(mon_mod, "record_event", lambda info: calls.append(info))

    # give a different path event
    class Evt:
        src_path = str(tmp_path / "other.file")

    handler.on_modified(Evt())
    assert not calls  # nothing recorded


def test_maybe_self_destruct_removes_file_when_flag_set(monkeypatch, tmp_path):
    """
    Ensure maybe_self_destruct actually unlinks when env var is '1'.
    """
    file = tmp_path / "watch.me"
    file.write_text("x")
    monkeypatch.setenv("ZILANT_SELF_DESTRUCT", "1")
    # direct call to reaction helper
    import zilant_prime_core.self_heal.monitor as m

    m.maybe_self_destruct(file)
    assert not file.exists()
