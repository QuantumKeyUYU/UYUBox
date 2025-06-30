# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import json


class SelfDestructError(Exception):
    """Raised when max-tries is reached on repeated opens."""

    pass


def pack_zil(
    payload: bytes,
    formula,
    lam: float,
    steps: int,
    key: bytes,
    salt: bytes,
    nonce: bytes,
    metadata: dict,
    max_tries: int,
    one_time: bool,
) -> bytes:
    """
    Minimal pack: header JSON + newline + raw payload.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("Payload must be bytes.")
    info = {
        "tries": metadata.get("tries", 0),
        "max_tries": max_tries,
        "one_time": one_time,
    }
    header = json.dumps(info, separators=(",", ":")).encode("utf-8")
    return header + b"\n" + payload


def unpack_zil(
    data: bytes,
    formula,
    key: bytes,
    out_dir: str = None,
) -> bytes:
    """
    Unpack and return payload, or raise SelfDestructError if tries exhausted.
    """
    if b"\n" not in data:
        raise ValueError("Invalid container format.")
    hdr, payload = data.split(b"\n", 1)
    try:
        info = json.loads(hdr.decode("utf-8"))
    except Exception:
        raise ValueError("Invalid container header.")
    tries = info.get("tries", 0)
    max_tries = info.get("max_tries", 0)
    one_time = info.get("one_time", False)
    if not one_time and (tries + 1) >= max_tries:
        raise SelfDestructError("Container self-destructed after max tries.")
    return payload
