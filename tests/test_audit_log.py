# tests/test_audit_log.py
from src.key_lifecycle import AuditLog


def test_audit_log_append_and_verify(tmp_path):
    path = tmp_path / "log.txt"
    log = AuditLog(path)
    # новый пустой файл — verify_log() True
    assert log.verify_log()

    # добавляем события
    log.append_event("first")
    log.append_event("second")
    assert log.verify_log()

    # портим последнюю строку
    lines = path.read_text().splitlines()
    bad = lines[:-1] + ["deadbeef wrong"]
    path.write_text("\n".join(bad), encoding="utf-8")
    assert not log.verify_log()
