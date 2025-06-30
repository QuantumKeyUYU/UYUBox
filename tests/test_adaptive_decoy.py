import pytest

from zilant_prime_core.zilfs import ZilantFS

pytestmark = pytest.mark.zilfs


def test_adaptive_decoy(tmp_path):
    cont = tmp_path / "c.zil"
    fs = ZilantFS(cont, b"x" * 32, decoy_profile="adaptive")
    files = list(fs.root.rglob("*"))
    assert len({p.relative_to(fs.root) for p in files}) >= 5
