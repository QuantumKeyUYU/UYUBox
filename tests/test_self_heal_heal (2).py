# tests/test_self_heal_heal.py
import json
import pytest

import zilant_prime_core.self_heal.heal as heal_mod
from zilant_prime_core.self_heal.heal import SelfHealFrozen, heal_container


class DummyRecordAction:
    calls = []

    @staticmethod
    def __call__(event, info):
        DummyRecordAction.calls.append((event, info))


class DummyProve:
    @staticmethod
    def __call__(digest):
        return b"proof-" + digest[:4]


@pytest.fixture(autouse=True)
def patch_dependencies(monkeypatch, tmp_path, tmp_path_factory):
    # Подменяем record_action, prove_intact и atomic_write
    import zilant_prime_core.self_heal.heal as module

    monkeypatch.setattr(module, "record_action", DummyRecordAction())
    monkeypatch.setattr(module, "prove_intact", DummyProve())
    # atomic_write → простая запись
    monkeypatch.setattr(module, "atomic_write", lambda p, b: p.write_bytes(b))
    yield


def make_container_file(tmp_path, meta_extra=None):
    # создаём файл-контейнер со стандартным HEADER_SEPARATOR
    hdr = {"magic": "ZILANT", "version": 1, "mode": "classic", "orig_size": 0, "checksum_hex": ""}
    if meta_extra:
        hdr.update(meta_extra)
    payload = b""
    blob = json.dumps(hdr).encode() + heal_mod.HEADER_SEPARATOR + payload
    f = tmp_path / "c.zil"
    f.write_bytes(blob)
    return f, blob


def test_heal_success(tmp_path):
    container, orig_blob = make_container_file(tmp_path)
    seed = b"x" * 32
    # первый проход: level 0 → 1
    ok = heal_container(container, b"k" * 32, rng_seed=seed)
    assert ok
    # backup .bak
    bak = container.with_suffix(".bak")
    assert bak.exists() and bak.read_bytes() == orig_blob
    # proof файл
    proof = container.with_suffix(".zil.proof")
    assert proof.read_bytes().startswith(b"proof-")
    # события записаны
    assert ("self_heal_triggered", {"file": str(container), "level": 1}) in DummyRecordAction.calls
    assert ("self_heal_done", {"file": str(container), "level": 1}) in DummyRecordAction.calls


def test_heal_cannot_lock(tmp_path):
    container, _ = make_container_file(tmp_path)
    lock = container.with_suffix(".lock")
    lock.write_bytes(b"")  # блокировка уже есть
    ok = heal_container(container, b"k" * 32, rng_seed=b"y" * 32)
    assert ok is False


def test_heal_bad_format(tmp_path):
    # нет HEADER_SEPARATOR → сразу False
    f = tmp_path / "bad.zil"
    f.write_bytes(b"nope")
    assert heal_container(f, b"k" * 32, rng_seed=b"z" * 32) is False


def test_heal_level_exceeded(tmp_path):
    # level >=3 → SelfHealFrozen
    meta = {"heal_level": 3, "heal_history": [], "recovery_key_hex": None}
    container, _ = make_container_file(tmp_path, meta_extra=meta)
    with pytest.raises(SelfHealFrozen):
        heal_container(container, b"k" * 32, rng_seed=b"q" * 32)
