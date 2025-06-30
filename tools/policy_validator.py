#!/usr/bin/env python3
"""Validate repository policies defined in .github/policies/policy.yaml."""
from __future__ import annotations

import subprocess
import sys
import yaml
from pathlib import Path

POLICY = Path(".github/policies/policy.yaml")
REPORT = Path("policy_report.md")


def changed_files() -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", "origin/main...HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [f for f in proc.stdout.split() if f]


def main() -> None:
    conf = yaml.safe_load(POLICY.read_text()) if POLICY.exists() else {}
    errors: list[str] = []
    files = changed_files()

    if conf.get("changelog") and "CHANGELOG.md" not in files:
        errors.append("CHANGELOG.md not updated")

    if conf.get("security_report") and not Path("security_compliance_report.md").exists():
        errors.append("security_compliance_report.md missing")

    if conf.get("coverage_min"):
        rate = 0.0
        cov_file = Path("coverage/coverage.xml")
        if cov_file.exists():
            text = cov_file.read_text()
            import re

            m = re.search(r'line-rate="([0-9.]+)"', text)
            if m:
                rate = float(m.group(1)) * 100
        if rate < conf["coverage_min"]:
            errors.append(f"coverage {rate:.1f}% < {conf['coverage_min']}")

    content = "# Policy validation report\n\n" + "\n".join(f"- {e}" for e in errors)
    if not content.endswith("\n"):
        content += "\n"
    REPORT.write_text(content)
    if errors:
        print("Policy violations detected:")
        for e in errors:
            print(e)
        sys.exit(1)
    print("All policies satisfied")


if __name__ == "__main__":
    main()
