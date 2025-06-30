# tests/test_self_heal_monitor.py
import pytest
import time

import zilant_prime_core.self_heal.monitor as mon_mod


@pytest.fixture(autouse=True)
def clear_env(monkeypatch, tmp_path):
    # чистый лог и отсутствие ZILANT_SELF_DESTRUCT
    monkeypatch.delenv("ZILANT_SELF_DESTRUCT", raising=False)
    (tmp_path / "dummy.txt").write_text("x")
    yield


def test_handler_triggers_all(monkeypatch, tmp_path):
    calls = []
    # подменяем реакции
    monkeypatch.setattr(mon_mod, "rotate_key", lambda k: calls.append(("rotate", k)))
    monkeypatch.setattr(mon_mod, "record_event", lambda info: calls.append(("record", info)))
    monkeypatch.setattr(mon_mod, "prove_intact", lambda d: calls.append(("prove", d)))
    monkeypatch.setenv("ZILANT_SELF_DESTRUCT", "1")
    # создаём файл и handler
    p = tmp_path / "dummy.txt"
    handler = mon_mod._Handler(p)

    # пишем файл, чтобы path.exists()==True, и создаём фейковый event
    class E:
        src_path = str(p)

    handler.on_modified(E())
    # проверяем, что всё вызвано
    assert any(c[0] == "rotate" for c in calls)
    assert any(c[0] == "record" for c in calls)
    assert any(c[0] == "prove" for c in calls)
    # и файл удалён
    assert not p.exists()


def test_monitor_container_no_watchdog(monkeypatch):
    # имитируем, что Observer не доступен
    monkeypatch.setitem(mon_mod.__dict__, "Observer", None)
    with pytest.raises(ImportError):
        mon_mod.monitor_container("somepath")


def test_monitor_container_lifecycle(monkeypatch, tmp_path):
    # тестируем что observer.start/stop/join вызываются, цикл прерывается
    events = []

    class DummyObs:
        def __init__(self):
            pass

        def schedule(self, h, path, recursive):
            events.append(("sched", path))

        def start(self):
            events.append("start")

        def is_alive(self):
            # запустим одну итерацию, потом завершить
            events.append("check")
            return False

        def stop(self):
            events.append("stop")

        def join(self):
            events.append("join")

    monkeypatch.setitem(mon_mod.__dict__, "Observer", DummyObs)
    # monkeypatch.sleep, чтобы тест не висел
    monkeypatch.setattr(time, "sleep", lambda t: None)
    # должен пройти без ошибок
    mon_mod.monitor_container(str(tmp_path / "dummy"))
    assert "start" in events and "stop" in events and "join" in events
