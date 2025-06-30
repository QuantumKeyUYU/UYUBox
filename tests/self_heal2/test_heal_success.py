from click.testing import CliRunner

from container import get_metadata, pack_file
from zilant_prime_core.cli import cli


def test_heal_success(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("hello")
    cont = tmp_path / "a.zil"
    key = b"k" * 32
    pack_file(src, cont, key)

    blob = cont.read_bytes()
    sep = blob.find(b"\n\n")
    cont.write_bytes(blob[: sep + 5])

    res = CliRunner().invoke(cli, ["heal-scan", str(cont), "--auto"])
    assert res.exit_code == 3

    meta = get_metadata(cont)
    assert meta["heal_level"] == 1
