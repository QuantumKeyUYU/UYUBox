#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Update SPDX headers for all Python files."""
from __future__ import annotations

import pathlib

HEADER = [
    "# SPDX-License-Identifier: MIT",
    "# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors",
    "",
]


def codify(path: pathlib.Path) -> None:
    text = path.read_text().splitlines()
    start = 0
    if text and text[0].startswith("#!"):
        start = 1
    lines = text[start:]
    while lines and lines[0].startswith("# SPDX"):
        lines.pop(0)
    new_lines = text[:start] + HEADER + lines
    path.write_text("\n".join(new_lines) + "\n")


def main() -> None:
    for file in pathlib.Path(".").rglob("*.py"):
        codify(file)


if __name__ == "__main__":
    main()
