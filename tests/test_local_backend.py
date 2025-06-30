# tests/test_local_backend.py
import os
import pytest
from pathlib import Path

import src.backends.local_backend as localb


def test_local_store_and_retrieve(tmp_path):
    data = b"hello"
    # меняем рабочую директорию на tmp_path
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        uri = localb.store(data)
        # возвращается путь, в котором есть имя файла .zil
        path = Path(uri)
        assert path.exists()
        loaded = localb.retrieve(uri)
        assert loaded == data
    finally:
        os.chdir(cwd)


def test_local_retrieve_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        localb.retrieve(str(tmp_path / "nope.zil"))
