# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

"""Test helpers."""

import importlib
import sys

# Provide tomli shim on Python 3.11+
if "tomli" not in sys.modules:
    sys.modules["tomli"] = importlib.util.module_from_spec(importlib.machinery.ModuleSpec("tomli", None))
