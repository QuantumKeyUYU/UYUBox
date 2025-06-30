# tests/test_monitor_importerror.py
import importlib
import pytest


def test_monitor_container_importerror(monkeypatch):
    monitor_mod = importlib.import_module("zilant_prime_core.self_heal.monitor")
    # Эмулируем отсутствие watchdog
    monkeypatch.setattr(monitor_mod, "Observer", None)
    with pytest.raises(ImportError):
        monitor_mod.monitor_container("fakepath")
