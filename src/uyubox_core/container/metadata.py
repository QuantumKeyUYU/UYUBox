# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
import json
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

__all__ = [
    "Metadata",
    "MetadataError",
    "deserialize_metadata",
    "new_meta_for_file",
    "serialize_metadata",
]


class MetadataError(Exception):
    """Любая ошибка, связанная с (де)сериализацией метаданных."""


@dataclass(eq=True)
class Metadata:
    filename: str
    size: int
    extra: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        filename: str | None = None,
        size: int | None = None,
        *,
        file: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if filename is None and file is None:
            raise MetadataError("`filename`/`file` is required")
        if size is None:
            raise MetadataError("`size` is required")
        self.filename = str(filename or file)
        self.size = int(size)
        self.extra = dict(extra or {})

    def to_dict(self) -> dict[str, Any]:
        return {"filename": self.filename, "size": self.size, **self.extra}

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> Metadata:
        try:
            fn = mapping.get("filename") or mapping["file"]
            sz = mapping["size"]
            extra = {k: v for k, v in mapping.items() if k not in {"filename", "file", "size"}}
            return cls(filename=str(fn), size=int(sz), extra=extra)
        except Exception as exc:
            raise MetadataError(str(exc)) from exc


def _bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _json_ready(mapping: MutableMapping[str, Any]) -> None:
    try:
        for k, v in list(mapping.items()):
            if isinstance(v, bytes):
                mapping[k] = _bytes_to_b64(v)
            elif isinstance(v, dict):
                _json_ready(v)
            elif isinstance(v, (list, tuple)):
                tmp = list(v)
                for i, item in enumerate(tmp):
                    if isinstance(item, bytes):
                        tmp[i] = _bytes_to_b64(item)
                    elif not isinstance(item, (str, int, float, bool, type(None))):
                        raise MetadataError("Unsupported type inside list")
                mapping[k] = tmp
            elif not isinstance(v, (str, int, float, bool, type(None))):
                raise MetadataError(f"Unsupported type: {type(v).__name__}")
    except Exception as e:
        raise MetadataError(str(e)) from e


def new_meta_for_file(path: Path) -> Metadata:
    st = path.stat()
    return Metadata(filename=path.name, size=st.st_size)


def serialize_metadata(meta: Metadata | dict[str, Any]) -> bytes:
    try:
        if isinstance(meta, Metadata):
            obj = meta.to_dict()
            _json_ready(obj)
            txt = json.dumps(obj, separators=(",", ":"))
        else:
            if not isinstance(meta, MutableMapping):
                raise MetadataError("meta must be Mapping or Metadata")
            obj = dict(meta)
            _json_ready(obj)
            txt = json.dumps(obj)
        return txt.encode("utf-8")
    except Exception as exc:
        raise MetadataError(str(exc)) from exc


def deserialize_metadata(raw: bytes | bytearray | memoryview) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], json.loads(bytes(raw).decode("utf-8")))
    except Exception as exc:
        raise MetadataError(str(exc)) from exc
