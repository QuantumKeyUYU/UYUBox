import hashlib
import os
import pytest
import tempfile
from pathlib import Path

from streaming_aead import pack_stream, resume_decrypt


@pytest.mark.slow
def test_stream_large(tmp_path: Path) -> None:
    psutil = pytest.importorskip("psutil")

    # create sparse 1 GiB file
    with tempfile.NamedTemporaryFile(delete=False) as src_tmp:
        src_tmp.seek(1 * 1024 * 1024 * 1024 - 1)
        src_tmp.write(b"\0")
    src = Path(src_tmp.name)

    key = os.urandom(32)
    container = tmp_path / "big.zst"
    pack_stream(src, container, key)

    have_bytes = int(container.stat().st_size * 0.55)
    out_file = tmp_path / "out.bin"
    resume_decrypt(container, key, have_bytes, out_file)

    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                data = fh.read(1024 * 1024)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()

    assert _sha256(src) == _sha256(out_file)
    rss = psutil.Process().memory_info().rss
    assert rss < 300 * 1024 * 1024

    src.unlink()
