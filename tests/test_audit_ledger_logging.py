import logging

import audit_ledger


def test_audit_ledger_records(caplog) -> None:
    caplog.set_level(logging.INFO)  # root-logger ловим
    audit_ledger.record_decoy_purged("x.zil")
    audit_ledger.record_decoy_removed_early("y.zil")

    joined = " | ".join(rec.getMessage() for rec in caplog.records)
    assert "decoy purged: x.zil" in joined
    assert "decoy removed early: y.zil" in joined
