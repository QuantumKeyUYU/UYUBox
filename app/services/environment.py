"""Device integrity and environment heuristics."""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass
class DeviceStatus:
    rooted: bool
    emulator: bool
    temperature_c: float
    battery_level: int


def probe_device() -> DeviceStatus:
    """Return mocked environment values until platform hooks are available."""

    return DeviceStatus(
        rooted=False,
        emulator=False,
        temperature_c=round(32 + random.random() * 6, 2),
        battery_level=random.randint(35, 95),
    )
