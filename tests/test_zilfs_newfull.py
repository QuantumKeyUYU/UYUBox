# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import importlib
import pytest
from pathlib import Path

# Импортируем модуль по актуальной структуре
try:
    zilfs = importlib.import_module("src.zilant_prime_core.zilfs")
except ModuleNotFoundError:
    zilfs = importlib.import_module("src.zilfs")

# Универсальный валидный ключ (32 байта)
KEY = b"p" * 32


def test_zero_file():
    f = zilfs._ZeroFile(10)
    assert f.read(4) == b"\0\0\0\0"
    assert f.read(10) == b"\0\0\0\0\0\0"
    assert f.read() == b""


def test_mark_sparse_not_nt(monkeypatch):
    monkeypatch.setattr("os.name", "posix")
    zilfs._mark_sparse(Path("fake.txt"))  # должен быть noop


def test_truncate_file(tmp_path):
    file = tmp_path / "f.txt"
    file.write_bytes(b"abcde")
    zilfs._truncate_file(file, 2)
    assert file.read_bytes() == b"ab"


def test_sparse_copyfile2(tmp_path):
    src = tmp_path / "src.bin"
    dst = tmp_path / "dst.bin"
    src.write_bytes(b"abcdef")
    zilfs._sparse_copyfile2(str(src), str(dst), 0)
    assert dst.exists()
    assert dst.stat().st_size == 6


def test_read_meta(tmp_path):
    file = tmp_path / "c.zil"
    meta = b'{"foo":42}\n\nrest'
    file.write_bytes(meta)
    res = zilfs._read_meta(file)
    assert res["foo"] == 42


def test_pack_unpack_dir(tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    (src / "a.txt").write_text("hi")
    dest = tmp_path / "cont.zil"
    zilfs.pack_dir(src, dest, KEY)
    out = tmp_path / "out"
    out.mkdir()
    zilfs.unpack_dir(dest, out, KEY)
    assert (out / "a.txt").read_text() == "hi"


def test_snapshot_diff(tmp_path):
    d = tmp_path / "dat"
    d.mkdir()
    (d / "f1.txt").write_text("1")
    cont = tmp_path / "file.zil"
    zilfs.pack_dir(d, cont, KEY)
    snap = zilfs.snapshot_container(cont, KEY, "lab1")
    (d / "f1.txt").write_text("2")
    zilfs.pack_dir(d, cont, KEY)
    snap2 = zilfs.snapshot_container(cont, KEY, "lab2")
    diff = zilfs.diff_snapshots(snap, snap2, KEY)
    assert any(v[0] != v[1] for v in diff.values())


def test_zilantfs_ro(tmp_path):
    cont = tmp_path / "ro.zil"
    cont.write_bytes(b'{"latest_snapshot_id":"x","label":"y"}\n\n')
    try:
        zilfs.ZilantFS(cont, KEY)
    except RuntimeError:
        pass  # должно падать из-за rollback detected


def test_zilantfs_decoy(tmp_path):
    cont = tmp_path / "d.zil"
    fs = zilfs.ZilantFS(cont, KEY, decoy_profile="minimal", force=True)
    assert fs.ro


def test_zilantfs_force(tmp_path):
    src = tmp_path / "in2"
    src.mkdir()
    (src / "a.txt").write_text("ok")
    cont = tmp_path / "n.zil"
    zilfs.pack_dir(src, cont, KEY)
    fs = zilfs.ZilantFS(cont, KEY, force=True)
    assert not fs.ro


def test_zilantfs_destroy(tmp_path):
    src = tmp_path / "in3"
    src.mkdir()
    (src / "a.txt").write_text("ok")
    cont = tmp_path / "ff.zil"
    zilfs.pack_dir(src, cont, KEY)
    fs = zilfs.ZilantFS(cont, KEY, force=True)
    fs.destroy("/")
    fs.destroy("/")  # destroy повторно — должен быть noop


def test_zilantfs_rw_check(tmp_path):
    src = tmp_path / "in4"
    src.mkdir()
    (src / "a.txt").write_text("ok")
    cont = tmp_path / "n2.zil"
    zilfs.pack_dir(src, cont, KEY)
    fs = zilfs.ZilantFS(cont, KEY, force=True)
    fs.ro = True
    with pytest.raises(zilfs.FuseOSError if hasattr(zilfs, "FuseOSError") else OSError):
        fs._rw_check()


def test_mount_umount_fs():
    with pytest.raises(RuntimeError):
        zilfs.mount_fs()
    with pytest.raises(RuntimeError):
        zilfs.umount_fs()
