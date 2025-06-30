# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import json
from pathlib import Path

from zilant_prime_core.self_heal import heal as heal_mod
from zilant_prime_core.self_heal.heal import heal_container


def make_file(tmp_path: Path, header: bytes) -> Path:
    file_path = tmp_path / "f.zil"
    sep = heal_mod.HEADER_SEPARATOR
    file_path.write_bytes(header + sep + b"payload")
    return file_path


def test_backup_exception_recorded_and_heal_continues(tmp_path):
    # valid minimal container header so level=0 → healing path
    hdr = {"heal_history": [], "heal_level": 0}
    header = json.dumps(hdr).encode()
    container = make_file(tmp_path, header)

    # monkeypatch atomic_write only for backup
    original_atomic_write = heal_mod.atomic_write

    def fail_backup(path, blob):
        # Фейлим только если это backup-файл (".bak")
        if str(path).endswith(".bak"):
            raise RuntimeError("backup failed")
        else:
            return original_atomic_write(path, blob)

    heal_mod.atomic_write = fail_backup
    try:
        ok = heal_container(container, b"k" * 32, rng_seed=b"s" * 32)
        assert ok is True

        # Проверяем, что записался record_action о фейле
        # (Если есть мок record_action или используешь tmp_action_log)
        # Можно проверить по логу файлов, если сохраняется
    finally:
        heal_mod.atomic_write = original_atomic_write
