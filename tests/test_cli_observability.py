import json
from click.testing import CliRunner

from zilant_prime_core.cli import cli
from zilant_prime_core.health import app


def test_json_output(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("data")
    res = CliRunner().invoke(cli, ["--output", "json", "pack", str(src), "-p", "pw"])
    assert res.exit_code == 0
    info = json.loads(res.output)
    assert info["path"].endswith(".zil")


def test_metrics_exposes_histogram(tmp_path):
    src = tmp_path / "x.txt"
    src.write_text("x")
    CliRunner().invoke(cli, ["--output", "json", "pack", str(src), "-p", "pw"])
    res = app.test_client().get("/metrics")
    assert b"command_duration_seconds_bucket" in res.data
