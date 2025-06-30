# tests/test_config.py
import src.config as cfg


def test_get_storage_backend_defaults_to_local(monkeypatch):
    monkeypatch.setattr(cfg, "BACKEND_TYPE", "whatever")
    module = cfg.get_storage_backend()
    assert module.__name__.endswith("local_backend")


def test_get_storage_backend_s3(monkeypatch):
    monkeypatch.setattr(cfg, "BACKEND_TYPE", "s3")
    module = cfg.get_storage_backend()
    assert module.__name__.endswith("s3_backend")


def test_get_storage_backend_ipfs(monkeypatch):
    monkeypatch.setattr(cfg, "BACKEND_TYPE", "ipfs")
    module = cfg.get_storage_backend()
    assert module.__name__.endswith("ipfs_backend")
