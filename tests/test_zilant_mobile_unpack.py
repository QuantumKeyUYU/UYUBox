# tests/test_zilant_mobile_unpack.py
import runpy
import sys
from pathlib import Path


def test_unpack_mobile_defaults(monkeypatch):
    # Capture arguments passed to unpack_dir
    captured = {}

    def fake_unpack_dir(src, dst, key):
        captured["args"] = (src, dst, key)

    # Monkey-patch the unpack_dir function in zilant_prime_core.zilfs
    monkeypatch.setattr("zilant_prime_core.zilfs.unpack_dir", fake_unpack_dir)

    # Simulate invocation with only src and dst (no key)
    monkeypatch.setattr(sys, "argv", ["unpack.py", "input.zil", "outdir"])
    runpy.run_module("zilant_mobile.unpack", run_name="__main__")

    src_arg, dst_arg, key_arg = captured["args"]
    assert src_arg == Path("input.zil")
    assert dst_arg == Path("outdir")
    # Expect default key of 32 zero bytes
    assert key_arg == b"\0" * 32


def test_unpack_mobile_with_hex_key(monkeypatch):
    captured = {}

    def fake_unpack_dir(src, dst, key):
        captured["args"] = (src, dst, key)

    monkeypatch.setattr("zilant_prime_core.zilfs.unpack_dir", fake_unpack_dir)

    # Simulate invocation with src, dst, and a hex key
    monkeypatch.setattr(sys, "argv", ["unpack.py", "in.zil", "outdir", "deadbeef"])
    runpy.run_module("zilant_mobile.unpack", run_name="__main__")

    src_arg, dst_arg, key_arg = captured["args"]
    assert src_arg == Path("in.zil")
    assert dst_arg == Path("outdir")
    # Hex 'deadbeef' → bytes.fromhex('deadbeef')
    assert key_arg == bytes.fromhex("deadbeef")
