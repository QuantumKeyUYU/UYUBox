#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Simple static security checklist for project sources.

The script scans ``src/`` and ``scripts/`` for risky Python constructs such as
``eval`` or ``subprocess`` usage. Results are written to
``python_security_report.md`` with a severity rating and remediation advice.
"""
from __future__ import annotations

import ast
from pathlib import Path

SRC_DIRS = [Path("src"), Path("scripts")]
REPORT = Path("python_security_report.md")


class Finding:
    def __init__(self, file: Path, line: int, desc: str, severity: str, rec: str) -> None:
        self.file = file
        self.line = line
        self.desc = desc
        self.severity = severity
        self.rec = rec

    def to_markdown(self) -> str:
        return f"- {self.file}:{self.line} **{self.severity}**: {self.desc}\n  - {self.rec}\n"


def check_file(path: Path) -> list[Finding]:
    text = path.read_text()
    tree = ast.parse(text)
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
                if isinstance(func.value, ast.Name):
                    base = func.value.id
                else:
                    base = ""
                name = f"{base}.{name}" if base else func.attr

            if name in {"eval", "exec"}:
                findings.append(Finding(path, node.lineno, f"use of {name}", "high", "Avoid dynamic execution of code"))
            elif name in {"pickle.load", "pickle.loads", "pickle.dump", "pickle.dumps"}:
                findings.append(Finding(path, node.lineno, f"{name} call", "high", "Prefer json or other safe formats"))
            elif name in {"os.system", "subprocess.call", "subprocess.Popen", "subprocess.run"}:
                findings.append(
                    Finding(path, node.lineno, f"{name} call", "medium", "Validate input and avoid shell=True")
                )
            elif isinstance(func, ast.Name) and func.id == "open":
                mode = None
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                if mode and any(ch in mode for ch in ("w", "a")):
                    findings.append(
                        Finding(path, node.lineno, "open() for writing", "low", "Ensure paths are validated")
                    )

    return findings


def main() -> None:
    all_findings: list[Finding] = []
    for d in SRC_DIRS:
        if d.exists():
            for f in d.rglob("*.py"):
                try:
                    all_findings.extend(check_file(f))
                except OSError:
                    continue

    if not all_findings:
        REPORT.write_text("No risky constructs detected.\n")
        return

    with REPORT.open("w") as fh:
        fh.write("# Python security report\n\n")
        for fnd in all_findings:
            fh.write(fnd.to_markdown())


if __name__ == "__main__":
    main()
