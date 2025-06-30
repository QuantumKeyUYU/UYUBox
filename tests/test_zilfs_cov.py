import os
import pytest
import subprocess

import zilant_prime_core.zilfs as zfs
from zilant_prime_core.zilfs import _truncate_file, _ZeroFile, pack_dir, unpack_dir


@pytest.mark.skipif(not hasattr(zfs, "_ORIG_COPYFILE2"), reason="Windows-only CopyFile2 fallback")
def test_sparse_copyfile2_winerror(monkeypatch, tmp_path):
    """
    Эмулируем WinError 112 в оригинальном CopyFile2 и проверяем,
    что _sparse_copyfile2 делает sparse-файл нужной длины.
    """
    # создаём исходник
    src = tmp_path / "big.bin"
    src.write_bytes(b"ABC")
    dst = tmp_path / "dst.bin"

    # подменяем оригинальный WinAPI
    def fake_copy(src_, dst_, flags, progress=None):
        err = OSError("no space")
        err.winerror = 112
        raise err

    # заменяем в namespace
    monkeypatch.setenv("ZILANT_STREAM", "0")
    monkeypatch.setattr(zfs, "_ORIG_COPYFILE2", fake_copy, raising=False)

    # вызываем patched copyfile2
    # (он поймает OSError с winerror=112 и вызовет _sparse_copyfile2)
    zfs._patched_copyfile2(str(src), str(dst), 0)

    assert dst.exists()
    assert dst.stat().st_size == 3
    assert dst.read_bytes() == b"\0" * 3


def test_pack_dir_stream_fifo(tmp_path, monkeypatch):
    """
    Тестируем код ветки mkfifo (без actual FIFO) на любой платформе.
    Просто проверяем, что pack_dir_stream создаёт контейнер.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "foo.txt").write_text("hello")
    out = tmp_path / "out.zil"
    key = b"x" * 32

    # Говорим pack_dir_stream считать себя на *nix
    monkeypatch.setenv("ZILANT_STREAM", "1")
    monkeypatch.setattr(os, "name", "posix", raising=False)
    # mkfifo-заглушка
    monkeypatch.setattr(os, "mkfifo", lambda path: None, raising=False)

    # stub процесса tar: вместо subprocess.Popen мы просто напишем заранее tar-файл
    class FakeProc:
        def __init__(*a, **k):
            pass

        def wait(self):
            pass

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProc(), raising=False)
    # stub pack_stream: просто запишем пустой контейнер
    monkeypatch.setattr(zfs, "pack_stream", lambda fifo, dest, key: dest.write_bytes(b"X"), raising=False)

    # Ветка должна отработать без ошибок
    zfs.pack_dir_stream(src, out, key)
    assert out.is_file()
    assert out.read_bytes() == b"X"


def test_snapshot_and_diff(tmp_path):
    """Проверяем snapshot_container + diff_snapshots."""
    # подготовка
    d = tmp_path / "d"
    d.mkdir()
    (d / "x.txt").write_text("one")
    key = b"p" * 32
    base = tmp_path / "base.zil"
    pack_dir(d, base, key)

    # snapshot v1
    snap1 = zfs.snapshot_container(base, key, "v1")

    # изменяем данные и snapshot v2
    unpack_dir(base, d, key)
    (d / "x.txt").write_text("two")
    pack_dir(d, base, key)
    snap2 = zfs.snapshot_container(base, key, "v2")

    diff = zfs.diff_snapshots(snap1, snap2, key)
    assert "x.txt" in diff
    assert diff["x.txt"][0] != diff["x.txt"][1]


def test_stub_mount_api():
    """mount_fs/umount_fs всегда бросают RuntimeError."""
    for fn in (zfs.mount_fs, zfs.umount_fs):
        with pytest.raises(RuntimeError):
            fn()


def test_throughput(tmp_path):
    """Проверяем throughput_mb_s ветку."""
    fs = zfs.ZilantFS(tmp_path / "c.zil", b"k" * 32, force=True)
    # пишем побольше данных
    (fs.root / "f.bin").write_bytes(b"\0" * 1024 * 1024)
    fs.destroy("/")
    val = fs.throughput_mb_s()
    assert isinstance(val, float) and val >= 0.0


def test_zerofile_and_truncate(tmp_path):
    """Покрываем _ZeroFile и _truncate_file."""
    # ZeroFile
    z = _ZeroFile(10)
    d1 = z.read(4)
    assert d1 == b"\0" * 4
    d2 = z.read()
    assert d2 == b"\0" * 6
    assert z.read() == b""

    # truncate
    f = tmp_path / "t.bin"
    f.write_bytes(b"ABCDEFGHIJ")
    _truncate_file(f, 3)
    assert f.read_bytes() == b"ABC"
