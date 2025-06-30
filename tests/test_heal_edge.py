import importlib
import json
import os
from pathlib import Path

heal = importlib.import_module("zilant_prime_core.self_heal.heal")
HDR_SEP = heal.HEADER_SEPARATOR


def _make(path: Path, hdr: dict):
    path.write_bytes(json.dumps(hdr).encode() + HDR_SEP + b"body")


def test_lock_file_exists(tmp_path):
    p = tmp_path / "c.zil"
    _make(p, {"heal_level": 0})
    # создаём .lock заранее -> ранний return False (стр. 47-49)
    p.with_suffix(".lock").touch()
    assert heal.heal_container(p, b"k" * 32, rng_seed=b"s" * 32) is False


def test_final_unlink_failure(tmp_path, monkeypatch):
    p = tmp_path / "c.zil"
    _make(p, {"heal_level": 0})
    monkeypatch.setattr(heal, "atomic_write", lambda *a, **k: None)
    monkeypatch.setattr(heal, "pack", lambda m, p, k: b"blob")
    monkeypatch.setattr(heal, "prove_intact", lambda d: None)

    # эмулируем ошибку при unlink(lock) в самом конце (стр. 108-109)
    def bad_unlink(path):
        raise FileNotFoundError

    monkeypatch.setattr(os, "unlink", bad_unlink)
    assert heal.heal_container(p, b"k" * 32, rng_seed=b"s" * 32) is True
