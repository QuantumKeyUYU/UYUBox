#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Detect potentially unused functions and classes in ``src/``.

This script performs a lightweight static analysis over the project sources to
identify functions and classes that are never referenced. The resulting list is
written to ``dead_code_report.md`` and can be used during code review.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
from typing import Iterable

SRC = Path("src")
DEFAULT_REPORT = Path("dead_code_report.md")


def _definitions(tree: ast.AST) -> Iterable[tuple[str, int]]:
    for node in tree.body:  # type: ignore[attr-defined]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name, node.lineno


def _used_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.ClassDef):
            for base in node.bases:
                if isinstance(base, ast.Name):
                    names.add(base.id)
                elif isinstance(base, ast.Attribute):
                    names.add(base.attr)
    return names


def main(report: str) -> None:
    definitions: dict[str, list[tuple[Path, int]]] = {}
    used: set[str] = set()
    for src in SRC.rglob("*.py"):
        try:
            text = src.read_text()
        except OSError:
            continue
        tree = ast.parse(text)
        for name, line in _definitions(tree):
            definitions.setdefault(name, []).append((src, line))
        used.update(_used_names(tree))

    dead = []
    for name, locs in definitions.items():
        if name not in used:
            for path, line in locs:
                dead.append((path, line, name))

    report_path = Path(report)
    if not dead:
        report_path.write_text("No dead code detected.\n")
        return

    with report_path.open("w") as fh:
        fh.write("# Dead code report\n\n")
        for path, line, name in sorted(dead, key=lambda x: (str(x[0]), x[1])):
            sig = f"class {name}" if name[:1].isupper() else f"{name}()"
            fh.write(f"- {path}:{line} `{sig}` - consider removing or adding tests/docs.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect unused functions/classes")
    parser.add_argument("--report", default=str(DEFAULT_REPORT), help="output report path")
    args = parser.parse_args()
    main(args.report)
