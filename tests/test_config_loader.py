# tests/test_config_loader.py

from pathlib import Path

import src.config as cfg


def test_load_option_fallback(monkeypatch, tmp_path):
    # Если pyproject.toml не читается, _load_option вернёт default
    monkeypatch.setattr(cfg, "ROOT", tmp_path)
    # Подменяем метод read_text, чтобы он всегда бросал
    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: (_ for _ in ()).throw(IOError("fail")))
    assert cfg._load_option("any", "def") == "def"


def test_pq_mode_and_backend_type_defaults(monkeypatch):
    # Подменяем _load_option, чтобы всегда возвращался default
    monkeypatch.setattr(cfg, "_load_option", lambda name, default: default)
    # Перезагружаем модуль, чтобы пересчитать константы
    import importlib

    importlib.reload(cfg)
    assert cfg.PQ_MODE == "classic"
    assert cfg.BACKEND_TYPE == "local"
