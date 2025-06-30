import hashlib
import os
import tempfile
from click.testing import CliRunner
from pathlib import Path

from streaming_aead import CHUNK
from zilant_prime_core.cli import cli


def _chunk_for_offset(container: Path, offset: int) -> int:
    with open(container, "rb") as fh:
        header = bytearray()
        while not header.endswith(b"\n\n"):
            header.extend(fh.read(1))
        pos = len(header)
        idx = 0
        while pos <= offset:
            clen = int.from_bytes(fh.read(4), "big")
            fh.seek(clen, os.SEEK_CUR)
            pos += 4 + clen
            idx += 1
        return idx


def _sha256(path: Path, start: int = 0) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        fh.seek(start)
        while True:
            buf = fh.read(1 << 20)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def test_cli_resume(tmp_path: Path) -> None:
    key = os.urandom(32)
    key_file = tmp_path / "k.bin"
    key_file.write_bytes(key)

    # create sparse 1 GiB source
    with tempfile.NamedTemporaryFile(delete=False) as src_tmp:
        src_tmp.seek(1 * 1024 * 1024 * 1024 - 1)
        src_tmp.write(b"\0")
    src = Path(src_tmp.name)

    container = tmp_path / "c.zst"
    runner = CliRunner()
    res = runner.invoke(cli, ["stream", "pack", str(src), str(container), "--key", str(key_file)])
    assert res.exit_code == 0, res.output

    offset = container.stat().st_size // 2
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    res = runner.invoke(
        cli,
        [
            "stream",
            "unpack",
            str(container),
            "--key",
            str(key_file),
            "--offset",
            str(offset),
            "--out-dir",
            str(out_dir),
        ],
    )
    assert res.exit_code == 0, res.output

    start_chunk = _chunk_for_offset(container, offset)
    result = _sha256(out_dir / container.stem, start=0)
    expect = _sha256(src, start=start_chunk * CHUNK)
    assert result == expect

    # tamper and expect failure
    with open(container, "r+b") as fh:
        fh.seek(offset + 32)
        b = fh.read(1)
        fh.seek(offset + 32)
        fh.write(bytes([b[0] ^ 0xFF]))

    res = runner.invoke(
        cli,
        [
            "stream",
            "unpack",
            str(container),
            "--key",
            str(key_file),
            "--offset",
            str(offset),
            "--out-dir",
            str(tmp_path / "bad"),
        ],
    )
    assert res.exit_code != 0

    src.unlink()
