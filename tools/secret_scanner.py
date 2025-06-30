#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
"""Search the repository and git history for leaked secrets."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPORT = Path("secret_leak_report.md")

PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "high", "Possible AWS access key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "high", "GitHub token"),
    (re.compile(r"eyJ[A-Za-z0-9._-]{20,}"), "medium", "Likely JWT token"),
    (re.compile(r"-----BEGIN(?: RSA)? PRIVATE KEY-----"), "critical", "Private key material"),
    (re.compile(r"(?i)password\s*=\s*['\"]?[^'\"\n]+"), "medium", "Hardcoded password"),
    (re.compile(r"(?i)secret"), "low", "Contains word 'secret'"),
    (re.compile(r"(?i)token"), "low", "Contains word 'token'"),
]


@dataclass
class Finding:
    location: str
    line: int
    desc: str
    severity: str
    context: str

    def to_md(self) -> str:
        return f"- {self.location}:{self.line} **{self.severity}** {self.desc}\n  `{self.context.strip()}`\n"


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return findings
    for i, line in enumerate(lines, 1):
        for pat, sev, desc in PATTERNS:
            if pat.search(line):
                findings.append(Finding(str(path), i, desc, sev, line.strip()))
    return findings


def scan_repo() -> list[Finding]:
    results: list[Finding] = []
    for p in Path(".").rglob("*"):
        if p.is_file() and not p.is_symlink() and ".git" not in p.parts:
            results.extend(scan_file(p))
    return results


def scan_history() -> list[Finding]:
    findings: list[Finding] = []
    try:
        log = subprocess.run(
            ["git", "log", "-p", "--unified=0", "--no-color"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=True,
        ).stdout.splitlines()
    except subprocess.CalledProcessError:
        return findings

    commit = ""
    file = ""
    for line in log:
        if line.startswith("commit "):
            commit = line.split()[1]
        elif line.startswith("+++ b/"):
            file = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            text = line[1:]
            for pat, sev, desc in PATTERNS:
                if pat.search(text):
                    loc = f"{file} (commit {commit})"
                    findings.append(Finding(loc, 0, desc, sev, text.strip()))
    return findings


def main() -> None:
    all_findings = scan_repo() + scan_history()
    if not all_findings:
        REPORT.write_text("No secrets detected.\n")
        return
    with REPORT.open("w") as fh:
        fh.write("# Secret leak report\n\n")
        for f in all_findings:
            fh.write(f.to_md())


if __name__ == "__main__":
    main()
