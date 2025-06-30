import hashlib
import pytest
from pathlib import Path

from zilant_prime_core.zilfs import ZilantFS, diff_snapshots, snapshot_container

pytestmark = pytest.mark.zilfs


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_snapshot_and_diff(tmp_path: Path) -> None:
    cont = tmp_path / "c.zil"
    pwd = b"x" * 32
    fs = ZilantFS(cont, pwd)
    (fs.root / "a.txt").write_text("a")
    fs.destroy("/")

    snap1 = snapshot_container(cont, pwd, "v1")

    fs2 = ZilantFS(cont, pwd, force=True)
    (fs2.root / "b.txt").write_text("b")
    fs2.destroy("/")

    snap2 = snapshot_container(cont, pwd, "v2")

    diff = diff_snapshots(snap1, snap2, pwd)
    assert "b.txt" in diff
