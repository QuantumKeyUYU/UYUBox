#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Generate skeleton tests for modules without tests."""
from __future__ import annotations

import pathlib

SRC = pathlib.Path("src")
TESTS = pathlib.Path("tests")


def main() -> None:
    for module in SRC.rglob("*.py"):
        rel = module.relative_to(SRC)
        test_file = TESTS / f"test_{module.stem}.py"
        if test_file.exists():
            continue
        module_path = ".".join(rel.with_suffix("").parts)
        skeleton = (
            "# SPDX-License-Identifier: MIT\n"
            "# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors\n\n"
            "import pytest\n\n"
            f"from {module_path} import *\n\n"
            "def test_placeholder():\n"
            "    assert True\n"
        )
        test_file.write_text(skeleton)


if __name__ == "__main__":
    main()
