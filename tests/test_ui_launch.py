import pytest
import subprocess
from pathlib import Path


@pytest.mark.skipif(not Path("ui/dist/zilant-ui").exists(), reason="ui not built")
def test_ui_help() -> None:
    res = subprocess.run(["ui/dist/zilant-ui", "--help"], capture_output=True)
    assert res.returncode == 0
