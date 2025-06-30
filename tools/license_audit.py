#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit dependency licenses from requirement files and pyproject."""
from __future__ import annotations

import argparse
import requests
import tomli
from packaging.requirements import InvalidRequirement, Requirement
from pathlib import Path

REQ_FILES = ["requirements.txt", "requirements-dev.txt"]
PYPROJECT = Path("pyproject.toml")
REPORT = Path("licenses_report.md")

APPROVED = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MPL-2.0",
    "GPL-2.0",
    "GPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
}
WARNING = {"AGPL-3.0"}


def parse_requirements(text: str) -> list[Requirement]:
    """Parse requirement lines safely, skipping comments and invalid entries."""
    reqs: list[Requirement] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            reqs.append(Requirement(line))
        except InvalidRequirement:
            print(f"WARNING: Skipped invalid requirement: {raw}")
    return reqs


def load_deps() -> dict[str, str]:
    deps: dict[str, str] = {}
    for f in REQ_FILES:
        p = Path(f)
        if p.exists():
            for req in parse_requirements(p.read_text()):
                deps[req.name] = str(req.specifier)
    if PYPROJECT.exists():
        data = tomli.loads(PYPROJECT.read_text())
        project = data.get("project", {})
        for dep in project.get("dependencies", []):
            req = Requirement(dep)
            deps[req.name] = str(req.specifier)
    return deps


def fetch_license(pkg: str) -> str:
    url = f"https://pypi.org/pypi/{pkg}/json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.ok:
            info = resp.json().get("info", {})
            license_field = info.get("license") or ""
            if not license_field:
                classifiers = info.get("classifiers", [])
                for c in classifiers:
                    if c.startswith("License ::"):  # e.g., License :: OSI Approved :: MIT License
                        parts = c.split("::")
                        if parts:
                            license_field = parts[-1].strip()
                            break
            return license_field or "UNKNOWN"
    except Exception:
        pass
    return "UNKNOWN"


def evaluate_status(license_name: str) -> str:
    license_upper = license_name.replace(" ", "").upper()
    if license_upper in APPROVED:
        return "approved"
    if license_upper in WARNING:
        return "warning"
    if "PROPRIETARY" in license_upper or "UNKNOWN" == license_upper:
        return "blocked"
    return "warning"


def generate_report(deps: dict[str, str]) -> None:
    lines = ["# Dependency license report", "", "| Package | Version | License | Status |", "|---|---|---|---|"]
    for pkg, ver in sorted(deps.items()):
        lic = fetch_license(pkg)
        status = evaluate_status(lic)
        lines.append(f"| {pkg} | {ver} | {lic} | {status} |")
    REPORT.write_text("\n".join(lines) + "\n")


def main() -> None:
    deps = load_deps()
    generate_report(deps)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.parse_args()
    main()
