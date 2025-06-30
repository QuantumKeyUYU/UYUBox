import pytest
import time

from kdf import derive_key


@pytest.mark.perf
def test_argon2_speed():
    start = time.time()
    derive_key(b"password", b"salt1234")
    assert time.time() - start < 2
