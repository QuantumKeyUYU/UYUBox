# tests/test_ipfs_backend.py
import pytest

import src.backends.ipfs_backend as ipfs


def test_ipfs_store_not_implemented():
    with pytest.raises(NotImplementedError):
        ipfs.store(b"data")


def test_ipfs_retrieve_not_implemented():
    with pytest.raises(NotImplementedError):
        ipfs.retrieve("anything")
