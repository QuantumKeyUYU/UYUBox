# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest

import zilant_prime_core.zilfs as zilfs

ZilantFS = zilfs.ZilantFS


@pytest.fixture
def dummy_dir(tmp_path):
    d = tmp_path / "testdir"
    d.mkdir()
    (d / "file1.txt").write_text("abc")
    (d / "file2.txt").write_text("xyz")
    sub = d / "subdir"
    sub.mkdir()
    (sub / "file3.txt").write_text("12345")
    return d


@pytest.fixture
def container_path(tmp_path):
    return tmp_path / "container.zil"


@pytest.fixture
def password():
    return b"k" * 32


def test_pack_unpack_dir(tmp_path, dummy_dir, container_path, password):
    zilfs.pack_dir(dummy_dir, container_path, password)
    out = tmp_path / "restored"
    zilfs.unpack_dir(container_path, out, password)
    assert (out / "file1.txt").read_text() == "abc"
    assert (out / "file2.txt").read_text() == "xyz"
    assert (out / "subdir/file3.txt").read_text() == "12345"


def test_pack_dir_stream(tmp_path, dummy_dir, container_path, password):
    zilfs.pack_dir_stream(dummy_dir, container_path, password)
    out = tmp_path / "r2"
    zilfs.unpack_dir(container_path, out, password)
    assert (out / "file1.txt").exists()
    assert (out / "file2.txt").exists()
    assert (out / "subdir/file3.txt").exists()


def test_read_meta_returns_meta(tmp_path, dummy_dir, container_path, password):
    zilfs.pack_dir(dummy_dir, container_path, password)
    meta = zilfs._read_meta(container_path)
    assert isinstance(meta, dict)
    assert meta.get("magic") == "ZILANT"


def test_read_meta_empty_returns_empty_dict(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"badheader")
    assert zilfs._read_meta(p) == {}


def test_truncate_file(tmp_path):
    f = tmp_path / "truncate.bin"
    f.write_bytes(b"abc" * 10)
    zilfs._truncate_file(f, 5)
    assert f.read_bytes() == b"abcab"


def test_zero_file():
    z = zilfs._ZeroFile(5)
    assert z.read(3) == b"\0\0\0"
    assert z.read(2) == b"\0\0"
    assert z.read(1) == b""


def test_sparse_copyfile2(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_bytes(b"A" * 100)
    zilfs._sparse_copyfile2(str(src), str(dst), 0)
    assert dst.stat().st_size == 100


def test_rewrite_metadata(tmp_path, dummy_dir, container_path, password):
    zilfs.pack_dir(dummy_dir, container_path, password)
    extra = {"x": 1}
    zilfs._rewrite_metadata(container_path, extra, password)
    meta = zilfs._read_meta(container_path)
    assert meta["x"] == 1


def test_snapshot_and_diff(tmp_path, dummy_dir, container_path, password):
    zilfs.pack_dir(dummy_dir, container_path, password)
    snap1 = zilfs.snapshot_container(container_path, password, "s1")
    out = tmp_path / "unpacked"
    zilfs.unpack_dir(container_path, out, password)
    (out / "file1.txt").write_text("NEW!")
    zilfs.pack_dir(out, container_path, password)
    snap2 = zilfs.snapshot_container(container_path, password, "s2")
    diff = zilfs.diff_snapshots(snap1, snap2, password)
    assert any("file1.txt" in k for k in diff)


def test_zilantfs_full_ci_lifecycle(tmp_path, dummy_dir, password):
    container = tmp_path / "fs.zil"
    fs = ZilantFS(container, password)
    testf = fs.root / "t.txt"
    with open(testf, "w") as f:
        f.write("hello world")
    stat = fs.getattr("/t.txt")
    assert stat["st_size"] == 11
    entries = fs.readdir("/", 0)
    assert "t.txt" in entries
    fd = fs.open("/t.txt", os.O_RDONLY)
    assert fs.read("/t.txt", 5, 0, fd) == b"hello"
    os.close(fd)
    fd = fs.create("/q.txt", 0o600)
    assert fs.write("/q.txt", b"abc", 0, fd) == 3
    fs.truncate("/q.txt", 2)
    os.close(fd)
    fs.throughput_mb_s()
    fs.destroy("/")
    fs2 = ZilantFS(container, password)
    assert (fs2.root / "t.txt").read_text() == "hello world"
    fs2.destroy("/")


def test_zilantfs_decoy_profile(tmp_path, password):
    container = tmp_path / "fs.zil"
    fs = ZilantFS(container, password, decoy_profile="minimal")
    assert (fs.root / "dummy.txt").exists()
    fs.destroy("/")


def test_zilantfs_decoy_profile_invalid(tmp_path, password):
    container = tmp_path / "fs.zil"
    with pytest.raises(ValueError):
        ZilantFS(container, password, decoy_profile="NO_SUCH_PROFILE")


def test_zilantfs_integrity_error(monkeypatch, tmp_path, password):
    container = tmp_path / "fs.zil"
    (tmp_path / "dummyfile").write_text("1")
    zilfs.pack_dir(tmp_path, container, password)

    def broken_unpack(*a, **kw):
        raise Exception("integrity")

    monkeypatch.setattr(zilfs, "unpack_dir", broken_unpack)
    fs = ZilantFS(container, password)
    assert fs.ro is True
    fs.destroy("/")


def test_zilantfs_force_skip_rollback(tmp_path, dummy_dir, container_path, password):
    zilfs.pack_dir(dummy_dir, container_path, password)
    meta = zilfs._read_meta(container_path)
    meta["latest_snapshot_id"] = "l1"
    meta["label"] = "other"
    zilfs._rewrite_metadata(container_path, meta, password)
    with pytest.raises(RuntimeError):
        ZilantFS(container_path, password)
    ZilantFS(container_path, password, force=True).destroy("/")


def test_zilantfs_helper_full(tmp_path, password):
    container = tmp_path / "fs.zil"
    fs = ZilantFS(container, password)
    p = fs.root / "to_del.txt"
    p.write_text("DEL")
    fs.unlink("/to_del.txt")
    assert not p.exists()
    fs.mkdir("/dirx", 0o700)
    assert (fs.root / "dirx").is_dir()
    fs.rmdir("/dirx")
    assert not (fs.root / "dirx").exists()
    a = fs.root / "a.txt"
    b = fs.root / "b.txt"
    a.write_text("foo")
    fs.rename("/a.txt", "/b.txt")
    assert b.exists()
    f = fs.root / "c.txt"
    fd = os.open(f, os.O_CREAT | os.O_WRONLY)
    fs.flush("/c.txt", fd)
    fs.release("/c.txt", fd)


def test_zilantfs_rw_check(tmp_path, password):
    container = tmp_path / "fs.zil"
    fs = ZilantFS(container, password, decoy_profile="minimal")
    with pytest.raises(zilfs.FuseOSError):
        fs._rw_check()
    with pytest.raises(zilfs.FuseOSError):
        fs.unlink("/dummy.txt")


def test_mount_umount_stub():
    with pytest.raises(RuntimeError):
        zilfs.mount_fs(None)
    with pytest.raises(RuntimeError):
        zilfs.umount_fs(None)


def test_zero_file_read_past_end():
    z = zilfs._ZeroFile(1)
    assert z.read(10) == b"\0"


def test_sparse_copyfile2_nonexistent(tmp_path):
    src = tmp_path / "nope"
    dst = tmp_path / "dst"
    with pytest.raises(FileNotFoundError):
        zilfs._sparse_copyfile2(str(src), str(dst), 0)
