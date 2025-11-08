import json
import os
import importlib
from pathlib import Path


def reload_logger(tmp_path):
    os.environ["ZILANT_AUDIT_DIR"] = str(tmp_path)
    import audit.logger as audit_logger

    importlib.reload(audit_logger)
    return audit_logger


def test_record_event_creates_signed_chain(tmp_path, monkeypatch):
    logger = reload_logger(tmp_path)

    first_path = logger.record_event("first", details={"value": 1})
    second_path = logger.record_event("second", details={"value": 2})

    assert first_path.exists()
    assert second_path.exists()
    assert first_path != second_path

    for path in (first_path, second_path):
        assert logger.verify_log(path)

    chain_state = (tmp_path / "chain.state").read_text().strip()
    second_data = json.loads(second_path.read_text())
    assert chain_state == second_data["chain_hash"]
    assert second_data["payload"]["prev_hash"] == json.loads(first_path.read_text())["chain_hash"]



def test_custom_directory_is_created(tmp_path):
    logger = reload_logger(tmp_path)

    # The directory should have been created during reload
    assert Path(logger.AUDIT_DIR) == tmp_path
    assert tmp_path.exists()

    log_path = logger.record_event("test")
    assert log_path.parent == tmp_path
