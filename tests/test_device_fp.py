# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from zilant_prime_core.utils.device_fp import SALT_CONST, collect_hw_factors, compute_fp, get_device_fingerprint


def test_device_fp_returns_string():
    assert isinstance(get_device_fingerprint(), str)


def test_collect_hw_factors_returns_dict(monkeypatch):
    monkeypatch.setattr("platform.processor", lambda: "CPU")
    monkeypatch.setattr("platform.machine", lambda: "x86")
    monkeypatch.setattr("platform.platform", lambda: "TestPlat")
    monkeypatch.setattr("platform.python_version", lambda: "3.12")
    monkeypatch.setattr("platform.node", lambda: "node")
    monkeypatch.setattr("uuid.getnode", lambda: 0x123456)
    monkeypatch.setattr("subprocess.check_output", lambda *a, **kw: b"")
    factors = collect_hw_factors()
    assert isinstance(factors, dict)
    for key in [
        "cpu_processor",
        "machine",
        "platform",
        "python_version",
        "node_name",
        "mac_address",
    ]:
        assert key in factors


def test_collect_hw_factors_windows(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr("subprocess.check_output", lambda *a, **kw: b"UUID\nABCD")
    factors = collect_hw_factors()
    assert "smbios_uuid" in factors


def test_compute_fp_changes_with_different_salts():
    hw = {"a": "1", "b": "2"}
    s1 = b"\x01" * 16
    s2 = b"\x02" * 16
    assert compute_fp(hw, s1) != compute_fp(hw, s2)
    assert len(compute_fp(hw, s1)) == 32


def test_compute_fp_type_errors():
    with pytest.raises(TypeError):
        compute_fp("bad", SALT_CONST)
    with pytest.raises(TypeError):
        compute_fp({}, "bad")
