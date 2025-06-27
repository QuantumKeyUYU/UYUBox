# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
"""
Утилиты для работы с «приманками» (decoy-файлами).
"""

from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path
from typing import Dict, List, Set

from audit_ledger import record_decoy_purged, record_decoy_removed_early
from container import get_metadata, pack_file

__all__ = [
    "generate_decoy_file",
    "generate_decoy_files",
    "is_decoy_file",
    "is_decoy_expired",
    "sweep_expired_decoys",
    "delete_expired_decoy_files",
    "clean_decoy_folder",
]

_DECOY_EXPIRY: Dict[Path, float] = {}
_DECOY_SET: Set[Path] = set()


# ---------------------------------------------------------------------
def generate_decoy_file(path: Path, *, size: int = 1024, expire_seconds: int | None = None) -> Path:
    """Сгенерировать одиночный decoy-контейнер."""
    tmp = path.with_name(f"tmp_{secrets.token_hex(4)}")
    tmp.write_bytes(secrets.token_bytes(size))

    pack_file(tmp, path, secrets.token_bytes(32))
    tmp.unlink(missing_ok=True)

    _DECOY_SET.add(path)
    if expire_seconds is not None:
        _DECOY_EXPIRY[path] = time.time() + expire_seconds

        def _cleanup() -> None:
            # выполняется в отдельном потоке
            time.sleep(expire_seconds)
            _DECOY_EXPIRY.pop(path, None)
            try:
                path.unlink()
                record_decoy_purged(str(path))
            except FileNotFoundError:  # pragma: no cover – ветка зависит от ручного удаления
                record_decoy_removed_early(str(path))  # pragma: no cover
            except Exception:  # pragma: no cover
                record_decoy_removed_early(str(path))  # pragma: no cover
            _DECOY_SET.discard(path)

        threading.Thread(target=_cleanup, daemon=True).start()

    return path


def generate_decoy_files(
    directory: Path, count: int, *, size: int = 1024, expire_seconds: int | None = None
) -> List[Path]:
    """Создать `count` decoy-файлов в каталоге `directory`."""
    directory.mkdir(parents=True, exist_ok=True)
    return [
        generate_decoy_file(directory / f"decoy_{secrets.token_hex(4)}.zil", size=size, expire_seconds=expire_seconds)
        for _ in range(max(0, count))
    ]


# ---------------------------------------------------------------------
def is_decoy_file(path: Path) -> bool:
    return path in _DECOY_SET


def is_decoy_expired(path: Path, max_age: float) -> bool:  # pragma: no cover – не используется в тестах
    if not is_decoy_file(path):
        return False
    try:
        return (time.time() - path.stat().st_mtime) >= max_age
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------
def sweep_expired_decoys(directory: Path) -> int:
    """
    Удалить decoy-файлы, чей TTL истёк. Возвращает количество удалённых.
    """
    now = time.time()
    removed = 0
    for p, expiry in list(_DECOY_EXPIRY.items()):
        if p.parent == directory and expiry <= now:
            try:
                p.unlink()
                record_decoy_purged(str(p))
            except FileNotFoundError:  # pragma: no cover
                record_decoy_removed_early(str(p))  # pragma: no cover
            except Exception:  # pragma: no cover
                record_decoy_removed_early(str(p))  # pragma: no cover
            finally:
                _DECOY_EXPIRY.pop(p, None)
                _DECOY_SET.discard(p)
                removed += 1
    return removed


def delete_expired_decoy_files(directory: Path, *, max_age: float = 3600) -> List[Path]:  # pragma: no cover
    """
    Удалить decoy-контейнеры в каталоге `directory`, у которых нельзя
    прочитать метаданные (значит файл повреждён/перезаписан).
    """
    deleted: List[Path] = []
    for p in sorted(_DECOY_SET):
        if p.parent != directory:
            continue
        try:
            get_metadata(p)  # если упадёт — файл битый
        except Exception:
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            _DECOY_SET.discard(p)
            _DECOY_EXPIRY.pop(p, None)
            deleted.append(p)
    return deleted


def clean_decoy_folder(directory: Path) -> int:  # pragma: no cover
    """Полностью очистить папку от decoy-файлов."""
    removed = 0
    for p in list(_DECOY_SET):
        if p.parent == directory:
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            _DECOY_SET.discard(p)
            _DECOY_EXPIRY.pop(p, None)
            removed += 1
    return removed
