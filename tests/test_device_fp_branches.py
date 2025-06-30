# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import builtins
import json
import platform
import subprocess
import sys
import time

from zilant_prime_core.utils import device_fp as df


def test_cpu_processor_exception(monkeypatch):
    # если platform.processor() падает — должно вернуться пустое значение
    monkeypatch.setattr(platform, "processor", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    factors = df.collect_hw_factors()
    assert factors["cpu_processor"] == ""


def test_bios_version_from_sysfs(monkeypatch, tmp_path):
    # for Linux: читаем /sys/class/dmi/id/bios_version
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    # подменим open, чтобы /sys/class/dmi/id/bios_version возвращал наш файл
    fake = tmp_path / "bios_version"
    fake.write_text("MYBIOS\nEXTRA")
    orig_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if path == "/sys/class/dmi/id/bios_version":
            return orig_open(fake, *args, **kwargs)
        return orig_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    # stub для остальных subprocess.check_output
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"")
    factors = df.collect_hw_factors()
    assert factors["bios_version"] == "MYBIOS"


def test_disk_serial_non_windows(monkeypatch):
    # для Linux-ветки disk_serial через lsblk
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"SERIAL123\nOTHER\n")
    factors = df.collect_hw_factors()
    assert factors["disk_serial"] == "SERIAL123"


def test_network_interfaces_with_psutil(monkeypatch):
    # проверяем, что если psutil доступен — возвращается JSON-строка
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"")

    # подвешиваем psutil в sys.modules
    class DummyPsutil:
        @staticmethod
        def net_if_addrs():
            return {"eth0": None, "lo": None}

    sys.modules["psutil"] = DummyPsutil
    factors = df.collect_hw_factors()
    nics = json.loads(factors["network_interfaces"])
    assert set(nics) == {"eth0", "lo"}
    # убираем «заглушку»
    del sys.modules["psutil"]


def test_entropy_jitter_failure(monkeypatch):
    # эмулируем ошибку в time.time() — должно получить пустую строку
    monkeypatch.setattr(time, "time", lambda: (_ for _ in ()).throw(OSError("fail")))
    factors = df.collect_hw_factors()
    assert factors["entropy_jitter"] == ""


def test_dummy_factor_always_present():
    # гарантируем, что dummy_factor есть всегда
    factors = df.collect_hw_factors()
    assert factors["dummy_factor"] == "zilant"
