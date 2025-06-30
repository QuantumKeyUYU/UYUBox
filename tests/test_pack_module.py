# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest
from pathlib import Path

from zilant_prime_core.container.pack import pack
from zilant_prime_core.container.unpack import unpack


def test_pack_unpack_roundtrip(tmp_path: Path):
    # ── подготовка ──
    src = tmp_path / "dragon.raw"
    payload = b"DRACARYS"
    src.write_bytes(payload)

    # ── pack() в памяти ──
    container = pack(src, password="🔥")

    # ── unpack из bytes → директория ──
    out_dir = tmp_path / "out"
    out_file = unpack(container, output_dir=out_dir, password="🔥")
    # содержимое обратно
    assert out_file.read_bytes() == payload
    # имя совпадает
    assert out_file.name == src.name

    # ── негатив: повторная распаковка выдаёт FileExistsError ──
    with pytest.raises(FileExistsError):
        unpack(container, output_dir=out_dir, password="🔥")
