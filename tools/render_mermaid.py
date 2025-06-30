#!/usr/bin/env python3
"""Render Mermaid diagrams to PNG.

Attempts to use mermaid-cli via ``npx``. If that fails, a simple
placeholder image is generated instead so that the docs build succeeds
without network access.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except Exception:  # pragma: no cover - pillow missing
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore


def render(src: Path, dst: Path) -> None:
    """Render ``src`` mermaid file into ``dst`` PNG."""
    cmd = [
        "npx",
        "-y",
        "@mermaid-js/mermaid-cli",
        "-i",
        str(src),
        "-o",
        str(dst),
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return
    except Exception:
        pass

    if Image is None or ImageDraw is None:
        dst.write_bytes(b"")
        return
    txt = src.read_text(encoding="utf-8")
    img = Image.new("RGB", (800, 200), "white")
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), txt, fill="black")
    img.save(dst)


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: render_mermaid.py INPUT.mmd OUTPUT.png", file=sys.stderr)
        return 1
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    render(src, dst)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
