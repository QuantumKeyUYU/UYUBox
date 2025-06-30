#!/usr/bin/env python3
"""
Генерирует SoA (Statement of Applicability) ISO 27001:2022 на основе YAML‑контролей.

YAML по умолчанию: docs/iso_controls.yml
Выход: docs/SoA_ISO27001.md

Если исходный YAML отсутствует — скрипт завершается с кодом 0 (чтобы CI не валился).
"""

from __future__ import annotations

import sys
import yaml
from pathlib import Path
from textwrap import indent

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "iso_controls.yml"
DST = ROOT / "docs" / "SoA_ISO27001.md"

if not SRC.exists():
    print(f"⚠  {SRC.relative_to(ROOT)} not found — skip SoA generation")
    sys.exit(0)

data = yaml.safe_load(SRC.read_text(encoding="utf-8")) or {}
if isinstance(data, dict) and "controls" in data:
    controls: list[dict[str, str]] = data["controls"]
else:
    controls = data if isinstance(data, list) else []

lines = ["# Statement of Applicability (ISO 27001:2022)\n"]
for ctrl in controls:
    lines.append(f"## {ctrl['id']} — {ctrl['name']}\n")
    rationale = ctrl.get("rationale", "—")
    lines.append("**Rationale**\n\n" + indent(rationale, "    ") + "\n")

DST.write_text("\n".join(lines), encoding="utf-8")
print("✅  SoA generated:", DST.relative_to(ROOT))
