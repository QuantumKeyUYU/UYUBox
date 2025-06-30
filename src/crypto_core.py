# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

import hashlib
from pathlib import Path
from typing import Union

__all__ = ["hash_sha3"]


def hash_sha3(data: Union[str, bytes, bytearray, Path], *, hex_output: bool = False) -> Union[bytes, str]:
    """Return SHA3-256 hash of the given data.

    ``data`` can be ``bytes``, ``bytearray``, string or :class:`~pathlib.Path`.
    If ``hex_output`` is ``True`` the hex digest is returned as ``str``.
    """
    if isinstance(data, Path):
        b = data.read_bytes()
    elif isinstance(data, str):
        b = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        b = bytes(data)
    else:
        raise TypeError("data must be bytes, str or Path")

    digest = hashlib.sha3_256(b).digest()
    return digest.hex() if hex_output else digest
