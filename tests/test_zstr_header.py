import json
import pytest
from pathlib import Path

from zilant_prime_core.zilfs import pack_dir_stream

pytestmark = pytest.mark.zilfs


def test_zstr_header(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("hi")
    dst = tmp_path / "c.zil"
    pack_dir_stream(src, dst, b"x" * 32)
    with open(dst, "rb") as fh:
        header = bytearray()
        while not header.endswith(b"\n\n"):
            header.extend(fh.read(1))
    meta = json.loads(header[:-2].decode())
    assert meta.get("magic") == "ZSTR"
