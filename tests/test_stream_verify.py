import os
from click.testing import CliRunner
from pathlib import Path

from streaming_aead import pack_stream
from zilant_prime_core.cli import cli


def test_stream_verify(tmp_path: Path) -> None:
    key = os.urandom(32)
    src = tmp_path / "src.bin"
    src.write_bytes(b"a" * 1024)
    container = tmp_path / "c.zst"
    pack_stream(src, container, key)

    runner = CliRunner()
    key_file = tmp_path / "k.bin"
    key_file.write_bytes(key)
    res = runner.invoke(cli, ["stream", "verify", str(container), "--key", str(key_file)])
    assert res.exit_code == 0, res.output

    with open(container, "r+b") as fh:
        fh.seek(-10, os.SEEK_END)
        b = fh.read(1)
        fh.seek(-10, os.SEEK_END)
        fh.write(bytes([b[0] ^ 0x01]))

    res = runner.invoke(cli, ["stream", "verify", str(container), "--key", str(key_file)])
    assert res.exit_code != 0
