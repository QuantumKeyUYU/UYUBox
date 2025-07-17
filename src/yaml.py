from __future__ import annotations

"""Minimal YAML utilities used for tests.
This stub provides ``safe_dump`` and ``safe_load`` compatible with a tiny subset
of YAML consisting of dictionaries with string keys and values that are scalars
or simple lists. It is not a full YAML parser and is only meant for the test
suite bundled with UYUBox.
"""

from typing import Any, Iterable
import json

__all__ = ["safe_dump", "safe_load"]


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        if value == "" or value.strip() != value or any(c in value for c in ":#"):
            return json.dumps(value)
        return value
    return json.dumps(value)


def _dump(obj: Any, indent: int = 0) -> Iterable[str]:
    space = " " * indent
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield f"{space}{k}:"
                yield from _dump(v, indent + 2)
            else:
                yield f"{space}{k}: {_scalar(v)}"
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                yield f"{space}-"
                yield from _dump(item, indent + 2)
            else:
                yield f"{space}- {_scalar(item)}"
    else:
        yield f"{space}{_scalar(obj)}"


def safe_dump(data: Any) -> str:
    """Return a minimal YAML representation of ``data``."""
    return "\n".join(_dump(data)) + "\n"


# --- loader ------------------------------------------------------------


def _parse_scalar(token: str) -> Any:
    if token.startswith('"') or token.startswith("'"):
        return json.loads(token)
    if token.lower() in {"true", "false", "null"}:
        return json.loads(token.lower())
    try:
        if token.startswith("0") and token != "0":
            # keep as string to avoid octal/hex confusion
            return token
        return int(token)
    except ValueError:
        try:
            return float(token)
        except ValueError:
            return token


def safe_load(text: str) -> Any:
    """Parse a very small subset of YAML produced by :func:`safe_dump`."""

    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    idx = 0

    def parse_block(indent: int) -> Any:
        nonlocal idx
        items: dict[str, Any] = {}
        seq: list[Any] | None = None
        while idx < len(lines):
            line = lines[idx]
            cur = len(line) - len(line.lstrip(" "))
            if cur < indent:
                break
            line = line[indent:]
            if line.startswith("- ") or line == "-":
                if items:
                    raise ValueError("Mixed mapping and sequence")
                if seq is None:
                    seq = []
                if line == "-":
                    idx += 1
                    seq.append(parse_block(indent + 2))
                else:
                    seq.append(_parse_scalar(line[2:].strip()))
                    idx += 1
            else:
                if seq is not None:
                    break
                if ":" in line:
                    key, rest = line.split(":", 1)
                    key = key.strip()
                    rest = rest.strip()
                    idx += 1
                    if rest:
                        items[key] = _parse_scalar(rest)
                    else:
                        # determine if next line starts a list
                        if idx < len(lines) and lines[idx].lstrip().startswith("-"):
                            items[key] = parse_block(indent + 2)
                        else:
                            items[key] = parse_block(indent + 2)
                else:
                    idx += 1
        if seq is not None:
            return seq
        return items

    result = parse_block(0)
    return result
