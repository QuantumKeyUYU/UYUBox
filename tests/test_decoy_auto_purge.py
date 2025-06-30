import time
from pathlib import Path

from zilant_prime_core import decoy_gen


def test_decoy_auto_purge(tmp_path: Path) -> None:
    dfile = decoy_gen.generate_decoy_file(tmp_path / "decoy.zil", size=64, expire_seconds=0.1)
    assert dfile.exists()
    time.sleep(0.15)
    assert decoy_gen.sweep_expired_decoys(tmp_path) == 1
    assert not dfile.exists()
