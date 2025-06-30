import importlib
from pathlib import Path

heal = importlib.import_module("zilant_prime_core.self_heal.heal")
mon = importlib.import_module("zilant_prime_core.self_heal.monitor")
HDR_SEP = heal.HEADER_SEPARATOR


def test_heal_bad_header_json(tmp_path: Path):
    """Линии 47-49 heal.py: плохой JSON → False"""
    bad = tmp_path / "b.zil"
    bad.write_bytes(b"{oops}\n\nX")
    assert heal.heal_container(bad, b"k" * 32, rng_seed=b"s" * 32) is False


def test_monitor_one_loop(monkeypatch, tmp_path: Path):
    """Линия 73 monitor.py: is_alive=True→False за один оборот."""
    state = {"ok": False}

    class Obs:
        def schedule(self, *a, **k): ...
        def start(self): ...
        def is_alive(self):
            state["ok"] = not state["ok"]
            return state["ok"]  # True → False

        def stop(self):
            state["stop"] = True

        def join(self):
            state["join"] = True

    monkeypatch.setattr(mon, "Observer", Obs)
    mon.monitor_container(str(tmp_path / "c.zil"))
    assert state.get("stop") and state.get("join")
