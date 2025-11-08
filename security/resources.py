"""Resource management helpers for cryptographic operations."""

from __future__ import annotations

from dataclasses import dataclass

import os
import shutil

from security.policy import policy


class ResourceError(RuntimeError):
    """Raised when resource constraints make an operation unsafe."""


@dataclass(frozen=True)
class DiskCapacity:
    total: int
    used: int
    free: int


def _resolve_directory(path: str) -> str:
    if os.path.isdir(path):
        return os.path.abspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    return directory or os.getcwd()


def _capacity_for(path: str) -> DiskCapacity:
    usage = shutil.disk_usage(path)
    return DiskCapacity(total=usage.total, used=usage.used, free=usage.free)


def _require_bytes(directory: str, required_bytes: int) -> None:
    capacity = _capacity_for(directory)
    headroom = policy.headroom_mb * 1024 * 1024
    minimum_free = policy.min_free_space_mb * 1024 * 1024
    threshold = max(required_bytes + headroom, minimum_free)
    if capacity.free < threshold:
        required_mb = threshold / (1024 * 1024)
        free_mb = capacity.free / (1024 * 1024)
        raise ResourceError(
            "Недостаточно свободного места: требуется минимум "
            f"{required_mb:.1f} МБ, доступно {free_mb:.1f} МБ."
        )


def ensure_pack_capacity(src_path: str, dest_path: str) -> None:
    """Ensure there is enough disk space to encrypt *src_path* into *dest_path*."""

    size = os.path.getsize(src_path)
    # AES-GCM streaming adds a nonce, header, tag, and temporary staging file.
    overhead = (policy.headroom_mb * 1024 * 1024) // 4 + 1_048_576
    required = size + overhead
    directory = _resolve_directory(dest_path)
    _require_bytes(directory, required)


def ensure_unpack_capacity(src_path: str, dest_path: str) -> None:
    """Ensure there is enough disk space to decrypt *src_path* into *dest_path*."""

    size = os.path.getsize(src_path)
    overhead = (policy.headroom_mb * 1024 * 1024) // 4
    required = size + overhead
    directory = _resolve_directory(dest_path)
    _require_bytes(directory, required)


__all__ = [
    "ResourceError",
    "ensure_pack_capacity",
    "ensure_unpack_capacity",
]
