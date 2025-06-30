import importlib
import pytest
import sys
import types


def get_zilfs():
    try:
        return importlib.import_module("src.zilant_prime_core.zilfs")
    except ModuleNotFoundError:
        return importlib.import_module("src.zilfs")


def test_fuse_import_block():
    modules = {}

    class DummyFuse:
        pass

    class DummyOps:
        pass

    class DummyOSError(Exception):
        pass

    modules["fuse"] = types.SimpleNamespace(FUSE=DummyFuse, Operations=DummyOps, FuseOSError=DummyOSError)
    sys_modules_bak = dict(sys.modules)
    sys.modules.update(modules)
    zilfs_mod = importlib.reload(get_zilfs())
    assert hasattr(zilfs_mod, "FUSE")
    assert hasattr(zilfs_mod, "Operations")
    assert hasattr(zilfs_mod, "FuseOSError")
    sys.modules.clear()
    sys.modules.update(sys_modules_bak)


def test_truncate_file_direct(tmp_path):
    zilfs = get_zilfs()
    fname = tmp_path / "file.txt"
    fname.write_bytes(b"abcdefghij")
    zilfs._truncate_file(fname, 4)
    assert fname.read_bytes() == b"abcd"


def test_destroy_exception_branch(tmp_path):
    zilfs = get_zilfs()
    src = tmp_path / "dir"
    src.mkdir()
    (src / "a.txt").write_text("hi")
    cont = tmp_path / "ff.zil"
    zilfs.pack_dir(src, cont, b"p" * 32)
    fs = zilfs.ZilantFS(cont, b"p" * 32, force=True)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(fs._tmp, "cleanup", lambda: (_ for _ in ()).throw(Exception("fail")))
    fs.destroy("/")
    monkeypatch.undo()
