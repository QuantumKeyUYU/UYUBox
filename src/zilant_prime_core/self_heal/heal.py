# src/zilant_prime_core/self_heal/heal.py
# SPDX-License-Identifier: MIT
"""Core logic for container self-healing."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import cast

from audit_ledger import record_action
from container import HEADER_SEPARATOR, pack
from crypto_core import hash_sha3
from utils.file_utils import atomic_write
from zilant_prime_core.crypto.fractal_kdf import fractal_kdf
from zilant_prime_core.zkp import prove_intact


class SelfHealFrozen(Exception):
    """Raised when heal limit is exceeded."""


def heal_container(path: Path, key: bytes, *, rng_seed: bytes) -> bool:
    """Attempt to self-heal *path* encrypted with *key*.

    Returns True if healing succeeded, otherwise False.
    """
    lock_path = path.with_suffix(".lock")
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    else:
        os.close(fd)

    try:
        blob = path.read_bytes()
        sep_index = blob.find(HEADER_SEPARATOR)
        if sep_index == -1:
            os.unlink(lock_path)
            return False
        header = blob[:sep_index]
        payload = blob[sep_index + len(HEADER_SEPARATOR) :]
        meta = json.loads(header.decode("utf-8"))
    except Exception:
        os.unlink(lock_path)
        return False

    level = int(meta.get("heal_level", 0))
    if level >= 3:
        os.unlink(lock_path)
        raise SelfHealFrozen(str(path))

    # Сохраняем резервную копию
    backup = path.with_suffix(".bak")
    try:
        atomic_write(backup, blob)
        record_action("self_heal_backup", {"file": str(path), "bak": str(backup)})
    except Exception as exc:
        record_action("self_heal_backup_failed", {"file": str(path), "error": str(exc)})
        # продолжаем, даже если бэкап не удался

    # Обновляем метаданные
    new_key = fractal_kdf(rng_seed)
    meta["heal_level"] = level + 1
    meta["recovery_key_hex"] = new_key.hex()

    history = list(meta.get("heal_history", []))
    history.append(hashlib.sha256(blob).hexdigest())
    meta["heal_history"] = history

    # Создаем новый контейнер
    try:
        new_blob = pack(meta, payload, new_key)
    except Exception as exc:
        record_action("self_heal_pack_failed", {"file": str(path), "error": str(exc)})
        os.unlink(lock_path)
        return False

    # Пишем новый контейнер
    try:
        atomic_write(path, new_blob)
    except Exception as exc:
        record_action("self_heal_write_failed", {"file": str(path), "error": str(exc)})
        os.unlink(lock_path)
        return False

    # Событие начала
    record_action("self_heal_triggered", {"file": str(path), "level": level + 1})

    # Генерируем и сохраняем доказательство
    try:
        digest = cast(bytes, hash_sha3(new_blob))
        proof = prove_intact(digest)
        path.with_suffix(path.suffix + ".proof").write_bytes(proof)
    except Exception as exc:
        record_action("self_heal_proof_failed", {"file": str(path), "error": str(exc)})
        # продолжаем, даже если доказательство не записалось

    # Событие завершения
    record_action("self_heal_done", {"file": str(path), "level": level + 1})

    # Удаляем lock
    try:
        os.unlink(lock_path)
    except FileNotFoundError:
        pass

    return True
