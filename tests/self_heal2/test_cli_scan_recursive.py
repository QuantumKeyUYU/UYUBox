from click.testing import CliRunner

from container import pack_file
from zilant_prime_core.cli import cli


def test_cli_scan_recursive(tmp_path):
    key = b"k" * 32
    files = []
    for i in range(3):
        src = tmp_path / f"f{i}.txt"
        src.write_text("data")
        cont = tmp_path / f"f{i}.zil"
        pack_file(src, cont, key)
        files.append(cont)

    # corrupt one
    bad = files[1]
    blob = bad.read_bytes()
    sep = blob.find(b"\n\n")
    bad.write_bytes(blob[: sep + 5])

    res = CliRunner().invoke(
        cli,
        ["heal-scan", str(tmp_path), "--recursive", "--auto", "--report", "json"],
    )
    assert res.exit_code == 3
