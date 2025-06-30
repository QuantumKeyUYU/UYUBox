import pytest
from pathlib import Path

from zilant_prime_core.zilfs import ZilantFS, snapshot_container

pytestmark = pytest.mark.zilfs


def test_antiroollback(tmp_path: Path) -> None:
    cont = tmp_path / "c.zil"
    pwd = b"x" * 32
    fs = ZilantFS(cont, pwd)
    (fs.root / "a").write_text("1")
    fs.destroy("/")
    snapshot_container(cont, pwd, "v1")
    with pytest.raises(RuntimeError):
        ZilantFS(cont, pwd)
    ZilantFS(cont, pwd, force=True)
