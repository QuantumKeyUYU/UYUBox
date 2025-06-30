import importlib

mon = importlib.import_module("zilant_prime_core.self_heal.monitor")


def test_monitor_happy_path(monkeypatch):
    # Подменяем Observer, чтобы is_alive()==False сразу -> строка 73 исполняется
    stopped = {"stop": False, "join": False}

    class FakeObs:
        def schedule(self, *a, **k):
            pass

        def start(self):
            pass

        def is_alive(self):
            return False

        def stop(self):
            stopped["stop"] = True

        def join(self):
            stopped["join"] = True

    monkeypatch.setattr(mon, "Observer", FakeObs)
    mon.monitor_container("dummy.zil")
    assert stopped["stop"] and stopped["join"]
