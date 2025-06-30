"""Гарантируем покрытие self-heal-логирования в audit_ledger.py."""

from __future__ import annotations

import json
import time
from pathlib import Path

from audit_ledger import record_self_heal_done, record_self_heal_triggered


def test_self_heal_events_are_logged(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    meta = {"node": "n1"}
    record_self_heal_triggered(meta)
    time.sleep(0.01)  # микропаузa, чтобы второй ts отличался
    record_self_heal_done(meta)

    ledger = Path("audit-ledger.jsonl")
    assert ledger.exists()

    actions = [json.loads(row)["action"] for row in ledger.read_text(encoding="utf-8").splitlines()]
    assert actions == ["self_heal_triggered", "self_heal_done"]
