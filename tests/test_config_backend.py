# tests/test_config_backend.py

import importlib
import pytest

import src.config as cfg


def reload_with_backend(backend: str):
    """
    Подменяем функцию чтения опций так, чтобы BACKEND_TYPE
    всегда возвращал нужное значение, затем перезагружаем модуль.
    """
    # type: ignore – мы намеренно переопределяем частную функцию
    cfg._load_option = lambda name, default: backend if name == "backend_type" else default  # type: ignore
    importlib.reload(cfg)
    return cfg


@pytest.mark.parametrize("backend", ["s3", "ipfs", "local"])
def test_get_storage_backend(monkeypatch, backend):
    cfg_module = reload_with_backend(backend)
    backend_module = cfg_module.get_storage_backend()

    # во всех случаях у модуля есть методы store и retrieve
    assert hasattr(backend_module, "store")
    assert hasattr(backend_module, "retrieve")

    # для локального бэкенда проверяем явно
    if backend == "local":
        assert backend_module.__name__.endswith("local_backend")
