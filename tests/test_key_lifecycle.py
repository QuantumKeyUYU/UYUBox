# tests/test_key_lifecycle.py

import pytest
from hashlib import sha256

import shamir
from src.key_lifecycle import AuditLog, KeyLifecycle, recover_secret, shard_secret


def test_empty_log_and_verify(tmp_path):
    f = tmp_path / "empty.log"
    f.write_text("")
    log = AuditLog(path=f)
    # для пустого файла просто возвращаем b""
    assert log._last_digest() == b""
    assert log.verify_log() is True


def test_append_corrupt_and_manual(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(path=log_path)
    assert log.verify_log()
    log.append_event("evt1")
    assert "evt1" in log_path.read_text()

    # испорченная запись → _last_digest == b""
    log_path.write_text("nothex evt\n")
    assert log._last_digest() == b""

    # вручную соберём правильный лог
    d = sha256(b"" + b"evt").digest().hex()
    good = tmp_path / "good.log"
    good.write_text(f"{d} evt\n")
    assert AuditLog(path=good).verify_log()

    # если хеш не совпадает — verify_log False
    bad = tmp_path / "bad.log"
    bad.write_text("00 evt\n")
    assert AuditLog(path=bad).verify_log() is False


def test_derive_and_rotate():
    master = b"\x01" * 32
    sess = KeyLifecycle.derive_session_key(master, "ctx")
    assert isinstance(sess, bytes) and len(sess) > 0

    rotated = KeyLifecycle.rotate_master_key(master, days=5)
    assert isinstance(rotated, bytes) and rotated != sess


def test_shard_and_recover():
    secret = (42).to_bytes(2, "big")
    shards = shard_secret(secret, n=3, t=2)
    assert len(shards) == 3
    rec = recover_secret(shards[:2])
    # сравним как числа, чтобы учесть ведущие нули
    assert int.from_bytes(rec, "big") == int.from_bytes(secret, "big")


@pytest.mark.parametrize("n,t", [(3, 0), (3, 4)])
def test_invalid_threshold(n, t):
    with pytest.raises(ValueError):
        shard_secret(b"\x00", n=n, t=t)


def test_secret_too_large():
    big = shamir._PRIME.to_bytes(16, "big")
    with pytest.raises(ValueError):
        shard_secret(big, n=1, t=1)


def test_recover_invalid():
    assert recover_secret([]) == b""
    with pytest.raises(ValueError):
        recover_secret([b"short"])
