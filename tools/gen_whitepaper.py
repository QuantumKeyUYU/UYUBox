#!/usr/bin/env python3
"""
Собирает одно PDF из Markdown‑глав проекта.

Главы (минимум ARCH.md и THREATS.md) должны лежать в docs/.
Опционально docs/OVERVIEW.md добавляется первой.
Метаданные берутся из docs/whitepaper.yml, если файл существует.

Выходной файл: dist/whitepaper.pdf
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
DIST = ROOT / "dist"
DIST.mkdir(exist_ok=True)

if shutil.which("pandoc") is None:
    sys.exit("❌  pandoc is not installed")

# Формируем список входных MD
sources: list[str] = []
if (DOCS / "OVERVIEW.md").exists():
    sources.append(str(DOCS / "OVERVIEW.md"))

for mandatory in ("ARCH.md", "THREATS.md"):
    md = DOCS / mandatory
    if not md.exists():
        sys.exit(f"❌  missing required {md.relative_to(ROOT)}")
    sources.append(str(md))

cmd = [
    "pandoc",
    *sources,
    "--pdf-engine=xelatex",  # работает с кириллицей
    "-V",
    "mainfont=DejaVu Serif",
    "-V",
    "monofont=DejaVu Sans Mono",
    "--toc",
    "-o",
    str(DIST / "whitepaper.pdf"),
]

meta = DOCS / "whitepaper.yml"
if meta.exists():
    cmd += ["--metadata-file", str(meta)]

print("🚀  pandoc build:", " ".join(cmd))
subprocess.run(cmd, check=True, text=True)
print("✅  whitepaper.pdf saved to", DIST)
