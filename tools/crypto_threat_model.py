#!/usr/bin/env python3
"""Automated crypto self-tests and threat model generation."""
from __future__ import annotations

import subprocess
from pathlib import Path

REPORT = Path("crypto_threat_report.md")
ASSETS = Path("docs/assets")
ASSETS.mkdir(parents=True, exist_ok=True)


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.stdout + proc.stderr


def main() -> None:
    sections = []
    out = run(["pytest", "tests/test_aead.py", "-q"])
    sections.append(f"## Crypto self-tests\n\n```\n{out}\n```")
    out = run(["python", "tools/atheris_fuzz.py", "--ci", "-runs=50"])
    sections.append(f"## Fuzz tests\n\n```\n{out}\n```")
    out = run(["python", "tools/gen_threat_diagram.py"])
    diagram = ASSETS / "threat_model.mmd"
    if Path("docs/threats.mmd").exists():
        Path("docs/threats.mmd").replace(diagram)
    sections.append(f"## Threat model\n\nDiagram saved to {diagram}\n")
    content = "# Crypto & Threat Report\n\n" + "\n".join(sections)
    if not content.endswith("\n"):
        content += "\n"
    REPORT.write_text(content)
    print(f"Report written to {REPORT}")


if __name__ == "__main__":
    main()
