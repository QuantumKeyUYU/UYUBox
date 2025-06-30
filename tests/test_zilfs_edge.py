import importlib
import pytest
import sys

zl = importlib.import_module("zilant_prime_core.zilfs")


def test_zero_import_block(monkeypatch):
    # Повторная перезагрузка без fuse -> строки 33-37
    if "zilant_prime_core.zilfs" in sys.modules:
        del sys.modules["zilant_prime_core.zilfs"]
    monkeypatch.setitem(sys.modules, "fuse", None)
    import importlib as _imp

    _imp.reload(importlib.import_module("zilant_prime_core.zilfs"))


def test_mark_sparse_full(monkeypatch, tmp_path):
    # строка 84 — ветка pragma no cover
    monkeypatch.setattr(zl.os, "name", "nt", raising=False)
    monkeypatch.setitem(sys.modules, "ctypes", None)
    zl._mark_sparse(tmp_path / "dummy")  # не должно упасть


def test_rollback_detected(monkeypatch, tmp_path):
    # строки 160-161
    cont = tmp_path / "c.zil"
    cont.touch()
    monkeypatch.setattr(zl, "get_metadata", lambda *_: {"latest_snapshot_id": "A", "label": "B"})
    with pytest.raises(RuntimeError):
        zl.ZilantFS(cont, b"pw")


def test_destroy_branches(tmp_path):
    # строки 234 и 251  (FileNotFoundError и повторный destroy)
    fs = zl.ZilantFS(tmp_path / "c.zil", b"pw", force=True)
    fs._tmp.cleanup()  # вызывает FileNotFoundError внутри destroy
    fs.destroy("/")
    fs.destroy("/")  # второй раз — ветка 251


def test_stub_mounts():
    # строки 374-375
    with pytest.raises(RuntimeError):
        zl.mount_fs()
    with pytest.raises(RuntimeError):
        zl.umount_fs()
