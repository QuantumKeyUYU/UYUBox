#!/usr/bin/env python3
"""Generate simple policy auto-fix suggestions."""
from __future__ import annotations

import yaml
from pathlib import Path

POLICY = Path(".github/policies/policy.yaml")
FIX = Path("policy_autofix.md")


def main() -> None:
    conf = yaml.safe_load(POLICY.read_text()) if POLICY.exists() else {}
    suggestions = ["# Policy auto-fix suggestions", ""]
    if conf.get("changelog") and not Path("CHANGELOG.md").exists():
        suggestions.append("- Add CHANGELOG entry")
    if conf.get("security_report") and not Path("security_compliance_report.md").exists():
        suggestions.append("- Run security_compliance_suite.py and commit report")
    FIX.write_text("\n".join(suggestions) + "\n")
    print(f"Suggestions written to {FIX}")


if __name__ == "__main__":
    main()
