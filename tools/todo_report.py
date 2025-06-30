#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect TODO and FIXME comments from project."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

SRC_DIRS = [Path("src"), Path("tools"), Path("scripts")]  # include tools and scripts
REPORT = Path("todo_report.md")
PATTERN = re.compile(r"#\s*(TODO|FIXME)(:.*)?", re.IGNORECASE)


def gather() -> list[tuple[Path, int, str]]:
    items = []
    for d in SRC_DIRS:
        if d.exists():
            for f in d.rglob("*.py"):
                try:
                    lines = f.read_text().splitlines()
                except OSError:
                    continue
                for i, line in enumerate(lines, 1):
                    m = PATTERN.search(line)
                    if m:
                        items.append((f, i, line.strip()))
    return items


def write(items: list[tuple[Path, int, str]]) -> None:
    if not items:
        REPORT.write_text("No TODO or FIXME comments found.\n")
        return
    with REPORT.open("w") as fh:
        fh.write("# TODO/FIXME report\n\n")
        for path, line, text in items:
            fh.write(f"- {path}:{line} `{text}`\n")


def main() -> None:
    items = gather()
    write(items)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gather TODO comments")
    parser.parse_args()
    main()
