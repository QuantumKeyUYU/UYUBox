import pytest

pytest.importorskip("pysnark")

from uyubox_core.zkp import prove_intact, verify_intact


def test_zkp_roundtrip():
    msg = b"event"
    proof = prove_intact(msg)
    assert verify_intact(msg, proof)
