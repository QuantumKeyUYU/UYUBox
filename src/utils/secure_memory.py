# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

__all__ = ["wipe_bytes"]

try:  # pragma: no cover - optional dependency
    import ctypes
    import ctypes.util

    _sodium = ctypes.CDLL(ctypes.util.find_library("sodium")) if ctypes.util.find_library("sodium") else None
except Exception:  # pragma: no cover - optional
    _sodium = None


def wipe_bytes(buf: bytearray) -> None:
    """Overwrite the given bytearray with zeros."""
    if not isinstance(buf, bytearray):
        raise TypeError("buf must be bytearray")
    if _sodium is not None:
        c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
        _sodium.sodium_memzero(c_buf, ctypes.c_size_t(len(buf)))
    else:
        for i in range(len(buf)):
            buf[i] = 0
