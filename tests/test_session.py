import importlib
import os

import pytest


def reload_session(tmp_path):
    os.environ["ZILANT_AUDIT_DIR"] = str(tmp_path)
    import audit.logger as audit_logger

    importlib.reload(audit_logger)
    import security.session as session_module

    return importlib.reload(session_module)


def test_session_expiry(monkeypatch, tmp_path):
    session_module = reload_session(tmp_path)

    base_time = 1000.0
    monkeypatch.setattr(session_module.time, "monotonic", lambda: base_time)

    token = session_module.session_manager.activate(ttl=1.0)
    assert token

    monkeypatch.setattr(session_module.time, "monotonic", lambda: base_time + 0.5)
    assert session_module.session_manager.require_active() == token

    monkeypatch.setattr(session_module.time, "monotonic", lambda: base_time + 5.0)
    with pytest.raises(session_module.SessionError) as exc:
        session_module.session_manager.require_active()
    assert "истекла" in str(exc.value)


def test_session_invalidate(monkeypatch, tmp_path):
    session_module = reload_session(tmp_path)

    base_time = 2000.0
    monkeypatch.setattr(session_module.time, "monotonic", lambda: base_time)
    session_module.session_manager.activate(ttl=5.0)
    session_module.session_manager.invalidate("threat detected")

    with pytest.raises(session_module.SessionError) as exc:
        session_module.session_manager.require_active()
    assert "threat detected" in str(exc.value)
