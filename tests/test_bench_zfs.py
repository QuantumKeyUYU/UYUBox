# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
import importlib
import os
import sys
import types

import utils.file_utils as file_utils  # atomic_write и os.fsync
from zilant_prime_core.bench_zfs import bench_fs


def _raise_attr(fd):  # noqa: D401
    """fsync, бросающий AttributeError для ветки except в bench_zfs."""
    raise AttributeError


def test_bench_fs_prometheus_ok(monkeypatch):
    """Ветка, когда prometheus_client доступен и Gauge.set вызывается."""
    fake = types.ModuleType("prometheus_client")

    class DummyGauge:  # noqa: D101
        def __init__(self, *_a, **_kw):  # noqa: D401
            self.value = None

        def set(self, v):  # noqa: D401
            self.value = v
            # дополнительно бросим Exception, чтобы попасть в except внутри bench_zfs
            raise RuntimeError("simulate gauge error")

    fake.Gauge = DummyGauge
    monkeypatch.setitem(sys.modules, "prometheus_client", fake)

    # fsync работает нормально
    monkeypatch.setattr(os, "fsync", lambda *_: None)
    monkeypatch.setattr(file_utils.os, "fsync", lambda *_: None)

    mb = bench_fs()
    # функция всё-равно возвращает положительный throughput
    assert mb > 0


def test_bench_fs_attrerror_path(monkeypatch):
    """Ветка, когда os.fsync не реализован → AttributeError."""
    # бросаем AttributeError при fsync в bench_zfs и в utils.file_utils.atomic_write
    monkeypatch.setattr(os, "fsync", _raise_attr)
    monkeypatch.setattr(file_utils.os, "fsync", _raise_attr)

    # patch atomic_write, импортированную в module `container`
    container_root = importlib.import_module("container")

    def safe_atomic(path, data):  # noqa: D401
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)

    monkeypatch.setattr(container_root, "atomic_write", safe_atomic, raising=True)

    # убираем prometheus_client, чтобы сработала ветка ImportError
    monkeypatch.setitem(sys.modules, "prometheus_client", None)

    assert bench_fs() > 0
