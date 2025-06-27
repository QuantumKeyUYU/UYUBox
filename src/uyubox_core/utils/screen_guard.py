# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from typing import Any, Iterator, Optional


class ScreenGuardError(Exception):
    pass


class ScreenGuard:
    _BLACKLIST = {"obs", "obs.exe", "ffmpeg", "ffmpeg.exe"}

    def __init__(self) -> None:
        try:
            import psutil

            self._psutil: Optional[Any] = psutil
        except ImportError:
            self._psutil = None

    def _iter_proc_names(self) -> Iterator[str]:
        if not self._psutil:
            return
        for proc in self._psutil.process_iter(attrs=["name"]):
            try:
                name = (proc.info.get("name") or "").lower()
            except Exception:
                continue
            if name:
                yield name

    def assert_secure(self) -> None:
        for name in self._iter_proc_names():
            if name in self._BLACKLIST or any(name.endswith(x) for x in self._BLACKLIST):
                raise ScreenGuardError(f"Screen capture tool detected: {name}")


guard = ScreenGuard()
