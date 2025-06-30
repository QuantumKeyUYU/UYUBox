import pytest
from pathlib import Path

from zilant_prime_core.utils.recovery import DECOY_FILE, DESTRUCTION_KEY_BUFFER, LOG_ENC_FILE, LOG_FILE, self_destruct


@pytest.fixture(autouse=True)
def setup_paths(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("zilant_prime_core.utils.recovery.LOG_FILE", tmp_path / "log.json")
    monkeypatch.setattr("zilant_prime_core.utils.recovery.LOG_ENC_FILE", tmp_path / "log.enc")
    globals()["LOG_FILE"] = tmp_path / "log.json"
    globals()["LOG_ENC_FILE"] = tmp_path / "log.enc"
    fake_decoy = tmp_path / "decoy.bin"
    fake_decoy.write_bytes(b"DEC OY DATA")
    monkeypatch.setattr("zilant_prime_core.utils.recovery.DECOY_FILE", fake_decoy)
    globals()["DECOY_FILE"] = fake_decoy
    monkeypatch.setattr(
        "zilant_prime_core.utils.recovery.DESTRUCTION_KEY_BUFFER",
        bytearray(b"\x01" * 32),
    )
    yield


def test_self_destruct_creates_encrypted_log_and_decoy(tmp_path: Path):
    LOG_FILE.write_bytes(b'{"event": "test"}')
    decoy = self_destruct("unit_test", DESTRUCTION_KEY_BUFFER)
    assert LOG_ENC_FILE.exists()
    enc_data = LOG_ENC_FILE.read_bytes()
    assert b"event" not in enc_data
    assert (Path.cwd() / "decoy.bin").exists()
    assert decoy == (Path.cwd() / "decoy.bin").read_bytes()


def test_self_destruct_without_log(tmp_path: Path):
    decoy = self_destruct("no_log", DESTRUCTION_KEY_BUFFER)
    assert not LOG_ENC_FILE.exists()
    assert decoy == (Path.cwd() / "decoy.bin").read_bytes()


def test_self_destruct_missing_decoy(tmp_path: Path):
    DECOY_FILE.unlink()
    with pytest.raises(FileNotFoundError):
        self_destruct("no_decoy", DESTRUCTION_KEY_BUFFER)


def test_self_destruct_bad_key_type(tmp_path: Path):
    with pytest.raises(RuntimeError):
        self_destruct("bad_key", "not_bytearray")  # type: ignore
