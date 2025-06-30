# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import importlib
import pytest


def get_zilfs():
    try:
        return importlib.import_module("src.zilant_prime_core.zilfs")
    except ModuleNotFoundError:
        return importlib.import_module("src.zilfs")


def test_pack_dir_stream_sparse(tmp_path):
    zilfs = get_zilfs()
    src = tmp_path / "big"
    src.mkdir()
    bigfile = src / "huge.bin"
    bigfile.write_bytes(b"X" * (2 * 1024 * 1024))  # 2MB
    dest = tmp_path / "cont.zil"
    zilfs.pack_dir_stream(src, dest, b"p" * 32)
    assert dest.exists()


def test_unpack_dir_missing_file(tmp_path):
    zilfs = get_zilfs()
    notafile = tmp_path / "none.zil"
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(FileNotFoundError):
        zilfs.unpack_dir(notafile, dest, b"p" * 32)


def test_zilantfs_destroy_double(tmp_path):
    zilfs = get_zilfs()
    src = tmp_path / "in"
    src.mkdir()
    (src / "a.txt").write_text("hi")
    cont = tmp_path / "ff.zil"
    zilfs.pack_dir(src, cont, b"p" * 32)
    fs = zilfs.ZilantFS(cont, b"p" * 32, force=True)
    # cleanup вызовет try/except внутри
    fs.destroy("/")
    # второй destroy: активирует except ValueError
    fs.destroy("/")


def test_sparse_pax_truncate(tmp_path):
    """Check that sparse pax header triggers _truncate_file logic (строка 251)"""
    zilfs = get_zilfs()
    src = tmp_path / "srcdir"
    src.mkdir()
    (src / "data.txt").write_text("data")
    dest = tmp_path / "container.zil"
    # Сначала создаём контейнер обычным путём (чтобы гарантировать pax-headers)
    zilfs.pack_dir_stream(src, dest, b"p" * 32)
    out = tmp_path / "unpacked"
    out.mkdir()
    # unpack_dir вызовет обработку pax_headers и _truncate_file
    zilfs.unpack_dir(dest, out, b"p" * 32)
    assert (out / "data.txt").read_text() == "data"


def test_winapi_mod_copyfile2_patch(monkeypatch):
    """Закрываем блок except ImportError в патчинге winapi_mod"""
    zilfs = get_zilfs()
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "_winapi":
            raise ImportError()
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    importlib.reload(zilfs)
    # возвращаем импорт чтобы не сломать систему
    monkeypatch.setattr(builtins, "__import__", real_import)
