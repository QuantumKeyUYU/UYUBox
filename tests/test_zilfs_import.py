import pytest

pytestmark = pytest.mark.zilfs


def test_zilfs_import() -> None:
    fuse = pytest.importorskip("fuse")
    assert fuse is not None
