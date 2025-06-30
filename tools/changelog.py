#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors
"""Append a version entry to CHANGELOG.md."""
from __future__ import annotations

import datetime
import pathlib
import sys

VERSION = sys.argv[1] if len(sys.argv) > 1 else "unreleased"
changelog = pathlib.Path("CHANGELOG.md")
now = datetime.date.today().isoformat()
entry = f"## {VERSION} - {now}\n- Maintenance updates.\n"
text = changelog.read_text().strip() + "\n" + entry
changelog.write_text(text)
