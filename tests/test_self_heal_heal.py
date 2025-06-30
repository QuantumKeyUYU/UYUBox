# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import json
import pytest

from zilant_prime_core.self_heal.heal import SelfHealFrozen, heal_container


def test_heal_container_lock_exists(tmp_path, monkeypatch):
    file = tmp_path / "cont.zil"
    file.write_bytes(b"anything")
    lock = tmp_path / "cont.lock"
    lock.write_text("lock")
    assert not heal_container(file, b"x" * 32, rng_seed=b"s" * 32)


def test_heal_container_bad_blob(tmp_path):
    file = tmp_path / "bad.zil"
    file.write_bytes(b"not a real container")
    # Нет HEADER_SEPARATOR, должно вернуть False
    assert not heal_container(file, b"x" * 32, rng_seed=b"s" * 32)


def test_heal_container_fail_json(tmp_path):
    file = tmp_path / "failjson.zil"
    sep = b"--SEP--"
    file.write_bytes(b"x" * 10 + sep + b"not-json")
    # HEADER_SEPARATOR не совпадает с тем, что ждет функция, но вызовет ошибку и вернет False
    assert not heal_container(file, b"x" * 32, rng_seed=b"s" * 32)


def test_heal_container_limit_and_success(tmp_path, monkeypatch):
    sep = b"--SEP--"
    # Подменяем HEADER_SEPARATOR на sep, pack и hash_sha3 на тривиальные функции
    monkeypatch.setattr("zilant_prime_core.self_heal.heal.HEADER_SEPARATOR", sep)
    monkeypatch.setattr("zilant_prime_core.self_heal.heal.pack", lambda meta, payload, key: b"blob")
    monkeypatch.setattr("zilant_prime_core.self_heal.heal.hash_sha3", lambda x: b"xxx")
    monkeypatch.setattr("zilant_prime_core.self_heal.heal.fractal_kdf", lambda x: b"\x99" * 32)
    monkeypatch.setattr("zilant_prime_core.self_heal.heal.prove_intact", lambda x: b"proof")
    monkeypatch.setattr("zilant_prime_core.self_heal.heal.record_action", lambda a, b=None: None)
    monkeypatch.setattr("zilant_prime_core.self_heal.heal.atomic_write", lambda p, b: p.write_bytes(b))
    # Создаем контейнер c heal_level=2 (следующий == 3, допустимо)
    meta = {"heal_level": 2, "heal_history": []}
    payload = b"PAYLOAD"
    file = tmp_path / "ok.zil"
    blob = json.dumps(meta).encode() + sep + payload
    file.write_bytes(blob)
    assert heal_container(file, b"x" * 32, rng_seed=b"s" * 32) is True

    # heal_level уже 3 — должно кидать SelfHealFrozen
    meta = {"heal_level": 3, "heal_history": []}
    file2 = tmp_path / "fail.zil"
    blob2 = json.dumps(meta).encode() + sep + payload
    file2.write_bytes(blob2)
    with pytest.raises(SelfHealFrozen):
        heal_container(file2, b"x" * 32, rng_seed=b"s" * 32)
