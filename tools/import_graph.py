#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate import dependency graph for ``src/``."""
from __future__ import annotations

import argparse
import ast
import subprocess
from pathlib import Path

SRC = Path("src")
DOT_FILE = Path("import_graph.dot")
SVG_FILE = Path("import_graph.svg")


def module_name(path: Path) -> str:
    return path.relative_to(SRC).with_suffix("").as_posix().replace("/", ".")


def collect_edges() -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    for file in SRC.rglob("*.py"):
        try:
            text = file.read_text()
        except OSError:
            continue
        tree = ast.parse(text)
        mod = module_name(file)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    edges.append((mod, alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                edges.append((mod, node.module))
    return edges


def write_dot(edges: list[tuple[str, str]]) -> None:
    lines = ["digraph imports {"]
    for src, dst in edges:
        if dst.startswith("zilant_prime_core"):
            lines.append(f'  "{src}" -> "{dst}";')
    lines.append("}")
    DOT_FILE.write_text("\n".join(lines) + "\n")


def render_svg() -> None:
    try:
        subprocess.run(["dot", "-Tsvg", str(DOT_FILE), "-o", str(SVG_FILE)], check=True)
    except Exception as e:
        print(f"dot failed: {e}")


def main(svg: bool) -> None:
    edges = collect_edges()
    write_dot(edges)
    if svg:
        render_svg()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate import graph")
    parser.add_argument("--svg", action="store_true", help="also render SVG with graphviz")
    args = parser.parse_args()
    main(args.svg)
