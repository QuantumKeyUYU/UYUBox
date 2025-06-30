# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import builtins
import os
import platform
import subprocess
import sys
import uuid

from zilant_prime_core.utils.device_fp import collect_hw_factors, compute_fp, get_device_fingerprint


def test_machine_exception(monkeypatch):
    monkeypatch.setattr(platform, "machine", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["machine"] == ""


def test_platform_exception(monkeypatch):
    monkeypatch.setattr(platform, "platform", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["platform"] == ""


def test_python_version_exception(monkeypatch):
    monkeypatch.setattr(platform, "python_version", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["python_version"] == ""


def test_node_name_exception(monkeypatch):
    monkeypatch.setattr(platform, "node", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["node_name"] == ""


def test_mac_address_exception(monkeypatch):
    monkeypatch.setattr(uuid, "getnode", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["mac_address"] == ""


def test_smbios_uuid_exception(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["smbios_uuid"] == ""


def test_bios_version_windows(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    data = b"SMBIOSBIOSVersion\nVER1\nOTHER"
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: data)
    factors = collect_hw_factors()
    assert factors["bios_version"] == "VER1"


def test_bios_version_sysfs_exception(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(builtins, "open", lambda *a, **k: (_ for _ in ()).throw(OSError("fail")))
    factors = collect_hw_factors()
    assert factors["bios_version"] == ""


def test_disk_serial_windows(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    data = b"SerialNumber\nDSERIAL\n"
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: data)
    factors = collect_hw_factors()
    assert factors["disk_serial"] == "DSERIAL"


def test_disk_serial_windows_exception(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["disk_serial"] == ""


def test_disk_serial_linux_exception(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["disk_serial"] == ""


def test_cpu_count_exception(monkeypatch):
    monkeypatch.setattr(os, "cpu_count", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = collect_hw_factors()
    assert factors["cpu_count"] == ""


def test_network_interfaces_exception(monkeypatch):
    # psutil present but net_if_addrs fails
    dummy = type(sys)("psutil")
    dummy.net_if_addrs = lambda: (_ for _ in ()).throw(RuntimeError("fail"))
    sys.modules["psutil"] = dummy
    factors = collect_hw_factors()
    assert factors["network_interfaces"] == ""
    del sys.modules["psutil"]


def test_compute_fp_normal():
    hw = {"x": "v", "y": "w"}
    salt = b"\x02" * 16
    fp = compute_fp(hw, salt)
    assert isinstance(fp, bytes) and len(fp) == 32


def test_get_device_fingerprint_format():
    fp = get_device_fingerprint()
    assert isinstance(fp, str) and len(fp) == 64
