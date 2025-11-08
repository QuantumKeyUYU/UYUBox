import os

from crypto_core.hybrid import HybridEncryptor
from crypto_core.profiles import Argon2Profile


class DummyEvent:
    def __init__(self):
        self._flag = False

    def is_set(self):
        return self._flag

    def set(self):
        self._flag = True


TEST_PROFILE = Argon2Profile("test", time_cost=1, memory_cost_kib=64 * 1024, parallelism=1)


def test_encrypt_decrypt_roundtrip(tmp_path):
    source = tmp_path / "plain.bin"
    source.write_bytes(os.urandom(1024))

    encrypted = tmp_path / "sealed.zil"
    decrypted = tmp_path / "plain.out"

    encryptor = HybridEncryptor(profile=TEST_PROFILE)

    progress_updates = []
    encryptor.encrypt_file(
        str(source),
        str(encrypted),
        "StrongPassword!1",
        progress_cb=lambda value: progress_updates.append(value),
    )

    assert encrypted.exists()
    assert progress_updates
    assert progress_updates[-1] == 1.0

    decrypt_updates = []
    encryptor.decrypt_file(
        str(encrypted),
        str(decrypted),
        "StrongPassword!1",
        progress_cb=lambda value: decrypt_updates.append(value),
    )

    assert decrypted.read_bytes() == source.read_bytes()
    assert decrypt_updates
    assert decrypt_updates[-1] == 1.0


def test_encrypt_cancel(tmp_path):
    source = tmp_path / "plain.bin"
    source.write_bytes(os.urandom(1024 * 1024))
    encrypted = tmp_path / "sealed.zil"

    encryptor = HybridEncryptor(profile=TEST_PROFILE)
    cancel = DummyEvent()

    def cancelling_progress(value):
        if value >= 0.0:
            cancel.set()

    try:
        encryptor.encrypt_file(
            str(source),
            str(encrypted),
            "StrongPassword!1",
            progress_cb=cancelling_progress,
            cancel_event=cancel,
        )
    except RuntimeError as exc:
        assert "Операция отменена" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("Encryption was expected to be cancelled")

    assert not encrypted.exists()
