import json
from click.testing import CliRunner

from zilant_prime_core.cli import cli


def test_pack_json(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("data")
    res = CliRunner().invoke(cli, ["--output", "json", "pack", str(src), "-p", "pw"])
    assert res.exit_code == 0
    info = json.loads(res.output)
    assert info["path"].endswith(".zil")


def test_unpack_yaml(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("x")
    pack = CliRunner().invoke(cli, ["pack", str(src), "-p", "pw"])
    assert pack.exit_code == 0
    cont = src.with_suffix(".zil")
    res = CliRunner().invoke(
        cli,
        ["--output", "yaml", "unpack", str(cont), "-p", "pw", "-d", str(tmp_path / "out")],
    )
    assert res.exit_code == 0
    assert "path:" in res.output
