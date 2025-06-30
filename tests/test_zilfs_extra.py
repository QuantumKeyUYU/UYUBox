# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest

from zilant_prime_core import zilfs


def test_pack_dir_missing_source(tmp_path):
    # src не существует
    with pytest.raises(FileNotFoundError):
        zilfs.pack_dir(tmp_path / "nope", tmp_path / "out.zil", b"k" * 32)


def test_unpack_dir_bad_key(tmp_path):
    # создаём правильный контейнер, но неправильный ключ
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_text("123")
    out = tmp_path / "out.zil"
    zilfs.pack_dir(src, out, b"k" * 32)
    # подставляем неверный ключ — ожидаем ValueError
    with pytest.raises(ValueError):
        zilfs.unpack_dir(out, tmp_path / "out", b"x" * 32)


def test_zilantfs_valueerror(tmp_path):
    # неправильный decoy_profile
    with pytest.raises(ValueError):
        zilfs.ZilantFS(tmp_path / "a.zil", b"k" * 32, decoy_profile="superinvalid")


def test_zilantfs_destroy_twice(tmp_path):
    key = b"k" * 32
    container = tmp_path / "a.zil"
    fs = zilfs.ZilantFS(container, key)
    fs.destroy("/")
    # Повторный destroy (не должен падать)
    fs.destroy("/")


def test_zilantfs_open_fail(tmp_path):
    key = b"k" * 32
    container = tmp_path / "a.zil"
    fs = zilfs.ZilantFS(container, key)
    # Нет такого файла — ожидаем FileNotFoundError
    with pytest.raises(FileNotFoundError):
        fs.open("/nope.txt", os.O_RDONLY)
    fs.destroy("/")


def test_snapshot_container_missing_file(tmp_path):
    # Файл не существует
    with pytest.raises(FileNotFoundError):
        zilfs.snapshot_container(tmp_path / "nope.zil", b"k" * 32, "snap")


def test_snapshot_container_wrong_type(tmp_path):
    # Некорректный путь (например, не файл, а директория)
    d = tmp_path / "folder"
    d.mkdir()
    with pytest.raises((ValueError, OSError)):
        zilfs.snapshot_container(d, b"k" * 32, "snap")
