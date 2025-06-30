import hashlib
import json
from click.testing import CliRunner
from pathlib import Path

from audit_ledger import record_action
from zilant_prime_core.cli import cli


def test_record_and_show(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record_action("A", {"x": 1})
    record_action("B", {"y": 2})
    record_action("C", {})
    lines = Path("audit-ledger.jsonl").read_text().splitlines()
    assert len(lines) == 3
    for line in lines:
        entry = json.loads(line)
        base = {k: entry[k] for k in ("timestamp", "action", "params")}
        digest = hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        assert entry["sha256"] == digest
    runner = CliRunner()
    res = runner.invoke(cli, ["ledger", "show", "--last", "2"])
    assert res.exit_code == 0
    assert len(res.output.strip().splitlines()) == 2
