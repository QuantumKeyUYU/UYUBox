import sys, pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import os
import tempfile

from universal_app import encrypt_file, decrypt_file


def test_encrypt_decrypt_roundtrip(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("hello")
    container = tmp_path / "container.bin"
    output = tmp_path / "out.txt"

    key = b"0" * 32
    encrypt_file(str(secret), str(container), key, max_tries=2)
    decrypt_file(str(container), str(output), key)
    assert output.read_text() == "hello"

    # second attempt should succeed (max_tries=2)
    decrypt_file(str(container), str(output), key)
    assert output.read_text() == "hello"

    # third attempt should fail
    try:
        decrypt_file(str(container), str(output), key)
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass


def test_one_time(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("data")
    container = tmp_path / "container.bin"
    out = tmp_path / "o.txt"

    key = b"x" * 32
    encrypt_file(str(secret), str(container), key, one_time=True)
    decrypt_file(str(container), str(out), key)

    try:
        decrypt_file(str(container), str(out), key)
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass
