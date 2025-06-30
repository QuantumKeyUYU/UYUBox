#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
"""Generate CHANGELOG_AUTO.md from git history."""
from __future__ import annotations

import subprocess
from datetime import date
from pathlib import Path

OUTPUT = Path("CHANGELOG_AUTO.md")

GROUPS = ["feat", "fix", "docs", "security", "chore", "other"]


def last_tag() -> str:
    try:
        tag = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return tag
    except subprocess.CalledProcessError:
        return ""


def collect_commits(tag: str) -> list[str]:
    range_spec = f"{tag}..HEAD" if tag else "HEAD"
    out = subprocess.run(
        ["git", "log", range_spec, "--pretty=%s"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def group_commits(commits: list[str]) -> dict[str, list[str]]:
    grouped = {g: [] for g in GROUPS}
    for msg in commits:
        lower_msg = msg.lower()
        for g in GROUPS[:-1]:
            if lower_msg.startswith(g) or lower_msg.startswith(f"[{g}]"):
                grouped[g].append(msg)
                break
        else:
            grouped["other"].append(msg)
    return grouped


def main() -> None:
    tag = last_tag()
    commits = collect_commits(tag)
    grouped = group_commits(commits)
    with OUTPUT.open("w") as fh:
        fh.write(f"# Auto-generated changelog\nGenerated: {date.today()}\n\n")
        fh.write(f"Since {tag or 'beginning'}\n\n")
        for g in GROUPS:
            if grouped[g]:
                title = g.capitalize()
                fh.write(f"## {title}\n")
                for c in grouped[g]:
                    fh.write(f"- {c}\n")
                fh.write("\n")


if __name__ == "__main__":
    main()
