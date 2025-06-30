# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_cli_cleanup.py

from pathlib import Path

import zilant_prime_core.cli as cli_mod


def test_cleanup_removes_existing(tmp_path):
    # подготовка: создаём контейнер и «старый» файл
    cont = tmp_path / "x.zil"
    cont.write_bytes(b"x\nPAY")
    old = tmp_path / "x"
    old.write_bytes(b"OLD")
    cli_mod._cleanup_old_file(cont)
    assert not old.exists()


def test_cleanup_no_file(tmp_path):
    # если файла нет — ничего не падает
    cont = tmp_path / "y.zil"
    cont.write_bytes(b"y\nPAY")
    cli_mod._cleanup_old_file(cont)  # не должно бросать


def test_cleanup_bad_container(tmp_path):
    # если read_bytes или split падает — мы его ловим
    cont = tmp_path / "bad.zil"
    cont.write_bytes(b"NOPART")
    # при split будет ValueError внутри cleanup
    cli_mod._cleanup_old_file(cont)  # не должно бросать


def test_cleanup_read_bytes_error(monkeypatch, tmp_path):
    # если read_bytes бросает — мы его ловим
    cont = tmp_path / "z.zil"
    cont.write_bytes(b"z\nPAY")
    monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(Exception("BOOM")))
    cli_mod._cleanup_old_file(cont)  # не должно бросать
