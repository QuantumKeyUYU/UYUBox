#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Generate docstring templates for CLI and API functions."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

SRC = Path("src")
REPORT = Path("cli_autodoc_report.md")


def find_cli_files() -> Iterable[Path]:
    yield SRC / "zilant_prime_core" / "cli.py"
    yield SRC / "zilant_prime_core" / "cli_commands.py"


def analyze_file(path: Path) -> list[dict[str, str]]:
    results = []
    text = path.read_text()
    tree = ast.parse(text)
    lines = text.splitlines()

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            name = node.name
            decorators = [ast.get_source_segment(text, d).strip() for d in node.decorator_list]
            if any("click." in dec and ("command" in dec or "group" in dec) for dec in decorators):
                doc = ast.get_docstring(node)
                if not doc or len(doc.strip()) < 10:
                    cmd = name.replace("_", "-")
                    doc_template = (
                        f"{cmd.replace('-', ' ').capitalize()} command.\n\n"
                        "Parameters:\n"
                        + "\n".join(f"    {a.arg}: TODO." for a in node.args.args if a.arg != "ctx")
                        + "\n\nExample:\n    zilant "
                        f"{cmd} [OPTIONS]"
                    )
                    results.append(
                        {
                            "file": str(path),
                            "line": str(node.lineno),
                            "type": "function",
                            "object": name,
                            "suggest": doc_template,
                        }
                    )
            # Check API functions (public, not starting with _ and outside CLI files)
            elif path.parts[1] != "zilant_prime_core" or path.name not in {"cli.py", "cli_commands.py"}:
                if not name.startswith("_"):
                    doc = ast.get_docstring(node)
                    if not doc or len(doc.strip()) < 10:
                        params = "\n".join(f"    {a.arg}: TODO." for a in node.args.args)
                        doc_template = f"{name} function.\n\n" "Parameters\n" "----------\n" + params + "\n"
                        results.append(
                            {
                                "file": str(path),
                                "line": str(node.lineno),
                                "type": "function",
                                "object": name,
                                "suggest": doc_template,
                            }
                        )
    # Option help detection
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("@click.option"):
            start = i
            snippet = line
            while not lines[i].rstrip().endswith(")") and i + 1 < len(lines):
                i += 1
                snippet += lines[i]
            if "help=" not in snippet:
                if lines[i].rstrip().endswith(")"):
                    suggestion = lines[i].rstrip().rstrip(")") + ', help="TODO")'
                else:
                    suggestion = lines[i].rstrip() + "  # TODO add help"
                results.append(
                    {
                        "file": str(path),
                        "line": str(start + 1),
                        "type": "option",
                        "object": snippet.strip(),
                        "suggest": suggestion,
                    }
                )
        i += 1
    return results


def main() -> None:
    entries = []
    for f in find_cli_files():
        if f.exists():
            entries.extend(analyze_file(f))
    for src in SRC.rglob("*.py"):
        if src.name in {"cli.py", "cli_commands.py"}:
            continue
        entries.extend(analyze_file(src))
    if not entries:
        REPORT.write_text("All CLI/API functions documented.\n")
        return
    with REPORT.open("w") as fh:
        fh.write("# CLI autodoc report\n\n")
        for e in entries:
            fh.write(f"- {e['file']}:{e['line']} {e['object']}\n")
            fh.write("```\n" + e["suggest"].rstrip() + "\n```\n\n")


if __name__ == "__main__":
    main()
