# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest

from zilant_prime_core import zilfs


def test_pack_unpack_dir(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("x")
    out = tmp_path / "out.zil"
    key = b"k" * 32
    zilfs.pack_dir(src, out, key)
    dst = tmp_path / "dst"
    zilfs.unpack_dir(out, dst, key)
    assert (dst / "a.txt").read_text() == "x"


def test_pack_dir_stream(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("y")
    out = tmp_path / "out.zil"
    key = b"k" * 32
    # For Windows — fallback branch, no mkfifo
    monkeypatch.setattr(os, "name", "nt")
    zilfs.pack_dir_stream(src, out, key)
    dst = tmp_path / "dst"
    zilfs.unpack_dir(out, dst, key)
    assert (dst / "a.txt").read_text() == "y"


def test_rewrite_metadata_and_snapshot(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("z")
    out = tmp_path / "out.zil"
    key = b"k" * 32
    zilfs.pack_dir(src, out, key)
    zilfs._rewrite_metadata(out, {"testkey": 1}, key)
    snap = zilfs.snapshot_container(out, key, "snap1")
    assert snap.exists()


def test_diff_snapshots(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("1")
    out1 = tmp_path / "o1.zil"
    out2 = tmp_path / "o2.zil"
    key = b"k" * 32
    zilfs.pack_dir(src, out1, key)
    (src / "a.txt").write_text("2")
    zilfs.pack_dir(src, out2, key)
    diff = zilfs.diff_snapshots(out1, out2, key)
    assert "a.txt" in diff


def test_zilantfs_decoy(monkeypatch, tmp_path):
    key = b"k" * 32
    container = tmp_path / "a.zil"
    # decoy_profile unknown
    with pytest.raises(ValueError):
        zilfs.ZilantFS(container, key, decoy_profile="unknown")
    # decoy_profile minimal
    fs = zilfs.ZilantFS(container, key, decoy_profile="minimal")
    assert fs.ro
    fs.destroy("/")


def test_zilantfs_create_write_read(tmp_path):
    key = b"k" * 32
    container = tmp_path / "a.zil"
    fs = zilfs.ZilantFS(container, key)
    fpath = "/b.txt"
    fd = fs.create(fpath, 0o600)
    fs.write(fpath, b"42", 0, fd)
    fs.flush(fpath, fd)
    fs.release(fpath, fd)
    fd = fs.open(fpath, os.O_RDONLY)
    data = fs.read(fpath, 2, 0, fd)
    fs.release(fpath, fd)
    assert data == b"42"
    fs.truncate(fpath, 1)
    fs.destroy("/")


def test_zilantfs_helpers(tmp_path):
    key = b"k" * 32
    container = tmp_path / "a.zil"
    fs = zilfs.ZilantFS(container, key)
    fs.mkdir("/d", 0o755)
    fs.rename("/d", "/e")
    fs.rmdir("/e")
    fs.destroy("/")
