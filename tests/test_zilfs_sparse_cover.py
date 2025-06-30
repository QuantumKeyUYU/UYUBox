# tests/test_zilfs_sparse_cover.py

import importlib


def get_zilfs():
    try:
        return importlib.import_module("src.zilant_prime_core.zilfs")
    except ModuleNotFoundError:
        return importlib.import_module("src.zilfs")


def test_unpack_dir_sparse(tmp_path):
    zilfs = get_zilfs()
    key = b"p" * 32
    # создаём каталог с большим (>1MiB) файлом
    src = tmp_path / "src"
    src.mkdir()
    large = src / "large.bin"
    data = b"x" * (1024 * 1024 + 1)
    large.write_bytes(data)
    # упаковываем через pack_dir_stream, чтобы появились pax_headers с ZIL_SPARSE_SIZE
    cont = tmp_path / "cont.zil"
    zilfs.pack_dir_stream(src, cont, key)
    # распаковываем — здесь внутри unpack_dir и _truncate_file() попадёт в строку 251
    out = tmp_path / "out"
    out.mkdir()
    zilfs.unpack_dir(cont, out, key)
    # проверяем, что размер восстановлен до оригинала
    assert (out / "large.bin").stat().st_size == len(data)
