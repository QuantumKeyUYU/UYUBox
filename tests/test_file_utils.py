# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from utils.file_utils import atomic_write, secure_delete


def test_atomic_write(tmp_path):
    target = tmp_path / "file.bin"
    data = b"hello"
    atomic_write(target, data)
    assert target.exists()
    assert target.read_bytes() == data


def test_secure_delete_nonexistent(tmp_path):
    path = tmp_path / "nofile"
    secure_delete(path)
    assert not path.exists()


def test_secure_delete_overwrites_and_removes(tmp_path):
    path = tmp_path / "file.bin"
    content = b"secret"
    path.write_bytes(content)
    assert path.exists()
    secure_delete(path)
    assert not path.exists()
