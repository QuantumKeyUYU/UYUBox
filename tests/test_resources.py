import importlib
from collections import namedtuple

import pytest


def reload_resources(monkeypatch, **overrides):
    keys = tuple(overrides.keys())
    for key, value in overrides.items():
        monkeypatch.setenv(key, str(value))
    policy_module = importlib.import_module("security.policy")
    resources_module = importlib.import_module("security.resources")
    reloaded_policy = importlib.reload(policy_module)
    reloaded_resources = importlib.reload(resources_module)
    return reloaded_policy, reloaded_resources, keys


def reset_modules(monkeypatch, policy_module, resources_module, keys):
    for key in keys:
        monkeypatch.delenv(key, raising=False)
    importlib.reload(policy_module)
    importlib.reload(resources_module)


def test_pack_capacity_blocks_when_space_low(tmp_path, monkeypatch):
    policy_module, resources_module, keys = reload_resources(
        monkeypatch,
        ZILANT_MIN_FREE_MB=10,
        ZILANT_HEADROOM_MB=4,
    )

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * 1024)

    Usage = namedtuple("Usage", "total used free")

    monkeypatch.setattr(
        resources_module.shutil,
        "disk_usage",
        lambda path: Usage(total=100, used=0, free=5 * 1024 * 1024),
    )

    with pytest.raises(resources_module.ResourceError):
        resources_module.ensure_pack_capacity(str(sample), str(tmp_path / "out.zilant"))

    reset_modules(monkeypatch, policy_module, resources_module, keys)


def test_unpack_capacity_allows_when_space_high(tmp_path, monkeypatch):
    policy_module, resources_module, keys = reload_resources(
        monkeypatch,
        ZILANT_MIN_FREE_MB=1,
        ZILANT_HEADROOM_MB=1,
    )

    sample = tmp_path / "sample.zil"
    sample.write_bytes(b"x" * 2048)

    Usage = namedtuple("Usage", "total used free")

    monkeypatch.setattr(
        resources_module.shutil,
        "disk_usage",
        lambda path: Usage(total=100, used=0, free=50 * 1024 * 1024),
    )

    resources_module.ensure_unpack_capacity(str(sample), str(tmp_path / "output.bin"))

    reset_modules(monkeypatch, policy_module, resources_module, keys)
