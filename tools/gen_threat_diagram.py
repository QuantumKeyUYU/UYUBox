#!/usr/bin/env python3
"""Generate Mermaid threat diagram from THREATS.md."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "THREATS.md"
DST = ROOT / "docs" / "threats.mmd"

if not SRC.exists():
    raise SystemExit(f"{SRC} not found")

inside = False
lines: list[str] = []
for line in SRC.read_text(encoding="utf-8").splitlines():
    if line.strip().startswith("```mermaid"):
        inside = True
        continue
    if inside and line.strip().startswith("```"):
        break
    if inside:
        lines.append(line)

if not lines:
    raise SystemExit("Mermaid block not found in THREATS.md")

DST.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Diagram written to {DST}")
