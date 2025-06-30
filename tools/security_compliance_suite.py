#!/usr/bin/env python3
"""Unified security and compliance audit suite."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPORT = Path("security_compliance_report.md")


def run(cmd: list[str]) -> tuple[str, int]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return proc.stdout + proc.stderr, proc.returncode
    except FileNotFoundError:
        return f"{cmd[0]} not installed\n", 1


def section(title: str, body: str) -> str:
    return f"## {title}\n\n{body}\n"


def semgrep_scan() -> tuple[str, str]:
    out, rc = run(["semgrep", "--config", ".semgrep", "--json"])
    Path("semgrep_report.json").write_text(out)
    status = "OK" if rc == 0 else "error"
    return status, f"Semgrep exit code {rc}"


def dead_code_scan() -> tuple[str, str]:
    out, rc = run(["python", "tools/dead_code_finder.py", "--report", "dead_code_report.md"])
    status = "OK" if rc == 0 else "error"
    return status, out


def secret_scan() -> tuple[str, str]:
    matches: list[str] = []
    pat = re.compile(r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|BEGIN PRIVATE KEY)")
    for p in Path(".").rglob("*.py"):
        try:
            text = p.read_text()
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                matches.append(f"{p}:{i}: {line.strip()}")
    status = "OK" if not matches else "error"
    body = "No secrets found." if not matches else "\n".join(matches)
    return status, body


def license_audit() -> tuple[str, str]:
    out, rc = run(["pip-licenses", "--format", "json"])
    Path("license_report.json").write_text(out)
    blocked: list[str] = []
    if rc == 0:
        try:
            data = json.loads(out)
            for pkg in data:
                lic = pkg.get("License", "").lower()
                if lic in {"agpl", "gpl-3.0", "unknown"}:
                    blocked.append(f"{pkg['Name']} - {lic}")
        except Exception:
            pass
    status = "OK" if not blocked else "error"
    body = "No blocked licenses." if not blocked else "\n".join(blocked)
    return status, body


def python_security() -> tuple[str, str]:
    out, rc = run(["python", "tools/python_security_checklist.py"])
    try:
        text = Path("python_security_report.md").read_text()
    except OSError:
        text = out
    status = "OK" if rc == 0 else "warning"
    return status, text


def todo_scan() -> tuple[str, str]:
    out, rc = run(["python", "tools/todo_report.py"])
    try:
        text = Path("todo_report.md").read_text()
    except OSError:
        text = out
    status = "OK" if rc == 0 else "warning"
    return status, text


def supply_chain_audit() -> tuple[str, str]:
    out, rc = run(["pip-audit", "-f", "markdown"])
    Path("supply_chain_audit.md").write_text(out)
    status = "OK" if rc == 0 else "warning"
    return status, out


def main() -> None:
    sections = []
    for title, func in [
        ("Semgrep", semgrep_scan),
        ("Dead code", dead_code_scan),
        ("Secret scan", secret_scan),
        ("License audit", license_audit),
        ("Dangerous calls", python_security),
        ("TODO/FIXME", todo_scan),
        ("Supply chain", supply_chain_audit),
    ]:
        status, body = func()
        sections.append(section(title + f" – {status}", body))

    content = "# Security & Compliance Report\n\n" + "\n".join(sections)
    if not content.endswith("\n"):
        content += "\n"
    REPORT.write_text(content)
    print(f"Report written to {REPORT}")


if __name__ == "__main__":
    main()
