# tests/test_self_heal_full.py
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import json
import pytest
from pathlib import Path

import zilant_prime_core.self_heal.heal as heal_mod
from zilant_prime_core.self_heal.heal import HEADER_SEPARATOR, SelfHealFrozen, heal_container


def make_file(tmp: Path, header: bytes) -> Path:
    p = tmp / "c.zil"
    p.write_bytes(header + HEADER_SEPARATOR + b"payload")
    return p


@pytest.fixture(autouse=True)
def cap_actions(monkeypatch):
    calls = []
    monkeypatch.setattr(heal_mod, "record_action", lambda act, p: calls.append((act, p)))
    return calls


def test_no_separator(tmp_path, cap_actions):
    # БLOB без разделителя → False без действий
    p = tmp_path / "x.zil"
    p.write_bytes(b"no header here")
    ok = heal_container(p, b"k" * 32, rng_seed=b"s" * 32)
    assert ok is False
    assert cap_actions == []


def test_over_heal_level(tmp_path):
    # Если level >=3 → SelfHealFrozen
    hdr = {"heal_level": 3}
    header = json.dumps(hdr).encode()
    p = tmp_path / "x.zil"
    p.write_bytes(header + HEADER_SEPARATOR + b"")
    with pytest.raises(SelfHealFrozen):
        heal_container(p, b"k" * 32, rng_seed=b"s" * 32)


def test_backup_fails_but_continues(tmp_path, cap_actions, monkeypatch):
    # atomic_write падает на бэкап, но процесс идёт дальше
    hdr = {"heal_level": 0, "heal_history": []}
    p = make_file(tmp_path, json.dumps(hdr).encode())

    def fa(path, data):
        if path.suffix == ".bak":
            raise RuntimeError("backup failed")
        return orig_write(path, data)

    orig_write = heal_mod.atomic_write
    monkeypatch.setattr(heal_mod, "atomic_write", fa)

    ok = heal_container(p, b"k" * 32, rng_seed=b"s" * 32)
    assert ok is True
    # Первая запись — self_heal_backup_failed
    assert cap_actions[0][0] == "self_heal_backup_failed"
    # Последняя — self_heal_done
    assert cap_actions[-1][0] == "self_heal_done"


def test_pack_and_write_fail(tmp_path, cap_actions, monkeypatch):
    # Падение pack → self_heal_pack_failed + False
    hdr = {"heal_level": 0, "heal_history": []}
    p = make_file(tmp_path, json.dumps(hdr).encode())
    monkeypatch.setattr(heal_mod, "pack", lambda m, payload, key: (_ for _ in ()).throw(RuntimeError("oops")))
    ok = heal_container(p, b"k" * 32, rng_seed=b"s" * 32)
    assert ok is False
    assert any(a == "self_heal_pack_failed" for a, _ in cap_actions)

    # Падение записи → self_heal_write_failed + False
    cap_actions.clear()
    p = make_file(tmp_path, json.dumps(hdr).encode())
    # Подделываем pack в норму, а atomic_write(path,...) второй раз падает
    monkeypatch.setattr(heal_mod, "pack", lambda m, payload, key: b"newblob")
    cnt = {"i": 0}

    def aw(path, data):
        cnt["i"] += 1
        if cnt["i"] > 1:
            raise IOError("disk full")
        return orig_aw(path, data)

    orig_aw = heal_mod.atomic_write
    monkeypatch.setattr(heal_mod, "atomic_write", aw)
    ok = heal_container(p, b"k" * 32, rng_seed=b"s" * 32)
    assert ok is False
    assert any(a == "self_heal_write_failed" for a, _ in cap_actions)


def test_proof_fail_does_not_abort(tmp_path, cap_actions, monkeypatch):
    # Если prove_intact падает — self_heal_proof_failed, но heal возвращает True
    hdr = {"heal_level": 0, "heal_history": []}
    p = make_file(tmp_path, json.dumps(hdr).encode())
    monkeypatch.setattr(heal_mod, "prove_intact", lambda d: (_ for _ in ()).throw(RuntimeError("bad proof")))
    # Stub pack/write to no-op
    monkeypatch.setattr(heal_mod, "atomic_write", lambda path, d: None)
    monkeypatch.setattr(heal_mod, "pack", lambda m, payload, key: b"blob")
    ok = heal_container(p, b"k" * 32, rng_seed=b"s" * 32)
    assert ok is True
    assert any(a == "self_heal_proof_failed" for a, _ in cap_actions)


def test_success_path(tmp_path, cap_actions, monkeypatch):
    # Полный успешный путь: все запись, trigger, done
    hdr = {"heal_level": 1, "heal_history": ["oldhash"]}
    p = make_file(tmp_path, json.dumps(hdr).encode())
    monkeypatch.setattr(heal_mod, "atomic_write", lambda path, data: None)
    monkeypatch.setattr(heal_mod, "pack", lambda m, payload, key: b"blob")
    monkeypatch.setattr(heal_mod, "prove_intact", lambda d: b"proof")
    # hash_sha3 возвращает что-то
    monkeypatch.setattr(heal_mod, "hash_sha3", lambda blob: b"digest")
    ok = heal_container(p, b"k" * 32, rng_seed=b"s" * 32)
    assert ok is True
    acts = [a for a, _ in cap_actions]
    assert "self_heal_backup" in acts
    assert "self_heal_triggered" in acts
    assert "self_heal_done" in acts
