# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

import zilant_prime_core.cli as cli_mod


def test_pack_bytes_success(tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"HELLO")
    dest = tmp_path / "out.zil"
    blob = cli_mod._pack_bytes(src, pwd="pwd", dest=dest, overwrite=False)
    assert blob.startswith(b"f.txt\n")
    assert blob.endswith(b"HELLO")


def test_pack_bytes_file_exists(tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"HELLO")
    dest = tmp_path / "out.zil"
    dest.write_bytes(b"OLD")
    with pytest.raises(FileExistsError):
        cli_mod._pack_bytes(src, pwd="pwd", dest=dest, overwrite=False)


def test_unpack_bytes_success(tmp_path):
    cont = tmp_path / "c.zil"
    cont.write_bytes(b"name\nPAYLOAD")
    out_dir = tmp_path / "d"
    result = cli_mod._unpack_bytes(cont, dest_dir=out_dir, pwd="pwd")
    assert result == out_dir / "name"
    assert (out_dir / "name").read_bytes() == b"PAYLOAD"


def test_unpack_bytes_container_too_small(tmp_path):
    cont = tmp_path / "c.zil"
    cont.write_bytes(b"NONELINE")
    out_dir = tmp_path / "d"
    with pytest.raises(ValueError) as exc:
        cli_mod._unpack_bytes(cont, dest_dir=out_dir, pwd="pwd")
    assert "too small" in str(exc.value).lower()


def test_unpack_bytes_file_exists(tmp_path):
    cont = tmp_path / "c.zil"
    cont.write_bytes(b"name\nDATA")
    out_dir = tmp_path / "d"
    # первый вызов создаст файл
    cli_mod._unpack_bytes(cont, dest_dir=out_dir, pwd="pwd")
    # второй — детектирует, что файл уже есть
    with pytest.raises(FileExistsError):
        cli_mod._unpack_bytes(cont, dest_dir=out_dir, pwd="pwd")
