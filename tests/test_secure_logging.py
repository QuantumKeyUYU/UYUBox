# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import base64
import os
import pytest
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zilant_prime_core.utils.secure_logging import SecureLogger, get_secure_logger


def test_secure_logger_roundtrip(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("ZILANT_LOG_KEY", base64.urlsafe_b64encode(key).decode())
    log_file = tmp_path / "sec.log"
    slog = SecureLogger(log_path=str(log_file))
    assert slog.read_logs() == []
    slog.log("Test\nInjection", "TEST")
    entries = slog.read_logs()
    assert entries == [("TEST", "Test\\nInjection")]


def test_get_secure_logger_singleton(tmp_path, monkeypatch):
    import zilant_prime_core.utils.secure_logging as sl_module

    monkeypatch.delenv("ZILANT_LOG_KEY", raising=False)
    sl_module._default = None
    log1 = str(tmp_path / "l1.log")
    log2 = str(tmp_path / "l2.log")
    slog1 = get_secure_logger(log_path=log1)
    slog2 = get_secure_logger(log_path=log2)
    assert slog1 is slog2
    assert slog1.log_path == log1


def test_secure_logger_invalid_line(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("ZILANT_LOG_KEY", base64.urlsafe_b64encode(key).decode())
    log_file = tmp_path / "bad.log"
    with open(log_file, "wb") as f:
        f.write(b"not|base64\n")
        f.write(b"onlyonepart\n")
        f.write(b"SGVsbG8=|SGVsbG8=\n")
    slog = SecureLogger(log_path=str(log_file))
    assert slog.read_logs() == []


def test_secure_logger_invalid_json(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("ZILANT_LOG_KEY", base64.urlsafe_b64encode(key).decode())
    log_file = tmp_path / "badjson.log"
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, b"{invalid json", None)
    with open(log_file, "wb") as f:
        f.write(base64.b64encode(nonce) + b"|" + base64.b64encode(ct) + b"\n")
    slog = SecureLogger(log_path=str(log_file))
    assert slog.read_logs() == []


def test_secure_logger_empty_file(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("ZILANT_LOG_KEY", base64.urlsafe_b64encode(key).decode())
    log_file = tmp_path / "empty.log"
    open(log_file, "wb").close()
    os.chmod(log_file, 0o600)
    slog = SecureLogger(log_path=str(log_file))
    assert slog.read_logs() == []


def test_secure_logger_file_missing_after_init(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("ZILANT_LOG_KEY", base64.urlsafe_b64encode(key).decode())
    log_file = tmp_path / "will_be_deleted.log"
    slog = SecureLogger(log_path=str(log_file))
    assert slog.read_logs() == []


def test_secure_logger_creates_nested_dir(tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("ZILANT_LOG_KEY", base64.urlsafe_b64encode(key).decode())
    nested_dir = tmp_path / "nested" / "dir"
    log_file = nested_dir / "secure.log"
    slog = SecureLogger(log_path=str(log_file))
    assert nested_dir.exists()
    assert not log_file.exists()
    slog.log("hello", "INFO")
    assert log_file.exists()
    entries = slog.read_logs()
    assert entries == [("INFO", "hello")]


def test_secure_logger_accepts_raw_bytes_key(tmp_path):
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "s.log")
    slog = SecureLogger(key=key, log_path=log_file)
    slog.log("payload", "LEVEL")
    entries = slog.read_logs()
    assert entries == [("LEVEL", "payload")]


def test_secure_logger_invalid_key_raises():
    with pytest.raises(ValueError):
        SecureLogger(key=b"short", log_path="x.log")


def test_get_secure_logger_singleton_isolation(tmp_path, monkeypatch):
    import zilant_prime_core.utils.secure_logging as sl_module

    monkeypatch.delenv("ZILANT_LOG_KEY", raising=False)
    sl_module._default = None
    log1 = str(tmp_path / "l1.log")
    log2 = str(tmp_path / "l2.log")
    slog1 = get_secure_logger(log_path=log1)
    slog2 = get_secure_logger(log_path=log2)
    assert slog1 is slog2
    assert slog1.log_path == log1


def test_secure_logger_fields_update(tmp_path):
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "fields.log")
    slog = SecureLogger(key=key, log_path=log_file)
    slog.log("test", "L1", foo="bar", id=7)
    entries = slog.read_logs()
    assert ("L1", "test") in entries
    assert any(
        tup[0] == "L1"
        and tup[1] == "test"
        and isinstance(tup[2], dict)
        and tup[2]["foo"] == "bar"
        and tup[2]["id"] == 7
        for tup in entries
        if len(tup) == 3
    )


def test_secure_logger_handles_corrupt_log(tmp_path):
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "corrupt.log")
    slog = SecureLogger(key=key, log_path=log_file)
    if not os.path.exists(log_file):
        open(log_file, "wb").close()
    with open(log_file, "ab") as f:
        f.write(b"not|a|valid|log\n")
    slog.log("hello", "INFO")
    entries = slog.read_logs()
    assert ("INFO", "hello") in entries


def test_secure_logger_fields_to_str(tmp_path):
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "fields.log")
    from zilant_prime_core.utils.secure_logging import SecureLogger as SL

    class DummyObj:
        def __str__(self):
            return "<DummyObj: str-representation>"

    slog = SL(key=key, log_path=log_file)
    slog.log(
        "Message",
        "LEVEL",
        foo=42,
        bar=None,
        arr=[1, 2, 3],
        obj=DummyObj(),
    )
    entries = slog.read_logs()
    assert any(
        tup[0] == "LEVEL" and tup[1] == "Message" and isinstance(tup[2], dict) for tup in entries if len(tup) == 3
    )
    for tup in entries:
        if len(tup) == 3 and tup[0] == "LEVEL" and tup[1] == "Message":
            fields = tup[2]
            assert fields["foo"] == 42
            assert fields["bar"] is None
            assert isinstance(fields["arr"], str)
            assert fields["arr"] == "[1, 2, 3]"
            assert isinstance(fields["obj"], str)
            assert fields["obj"] == "<DummyObj: str-representation>"


def test_skip_line_without_separator(tmp_path):
    log_file = str(tmp_path / "skip.log")
    slog = SecureLogger(key=secrets.token_bytes(32), log_path=log_file)
    with open(log_file, "ab") as f:
        f.write(b"this_is_not_valid_log_line\n")
    assert slog.read_logs() == []


def test_tampered_line_restores(tmp_path):
    key = secrets.token_bytes(32)
    log_file = str(tmp_path / "tamper.log")
    slog = SecureLogger(key=key, log_path=log_file)
    slog.log("First entry", "INFO")
    slog.log("Second entry", "DEBUG")
    with open(log_file, "r+b") as f:
        lines = f.readlines()
        f.seek(len(lines[0]))
        f.write(b"invalid|line\n")
    entries = slog.read_logs()
    assert ("INFO", "First entry") in entries
    assert ("DEBUG", "Second entry") not in entries


def test_secure_logger_bad_key(tmp_path):
    import zilant_prime_core.utils.secure_logging as secure_logging

    with pytest.raises(ValueError):
        secure_logging.SecureLogger(key=b"short", log_path=str(tmp_path / "x.log"))


def test_get_secure_logger_singleton_and_env(tmp_path, monkeypatch):
    import zilant_prime_core.utils.secure_logging as secure_logging

    secure_logging._default = None
    monkeypatch.delenv("ZILANT_LOG_KEY", raising=False)
    log_path = str(tmp_path / "singleton.log")
    slog1 = secure_logging.get_secure_logger(log_path=log_path)
    assert isinstance(slog1, secure_logging.SecureLogger)
    assert "ZILANT_LOG_KEY" in os.environ
    slog2 = secure_logging.get_secure_logger(log_path=log_path)
    assert slog1 is slog2
    key = secrets.token_bytes(32)
    another_log_path = str(tmp_path / "another.log")
    slog3 = secure_logging.get_secure_logger(key=key, log_path=another_log_path)
    assert slog3 is slog1
    slog1.log("TOP_SECRET", "SECRET_MESSAGE")
    entries = slog1.read_logs()
    assert ("SECRET_MESSAGE", "TOP_SECRET") in entries
