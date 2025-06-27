# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

__version__ = "0.9.9b2"

__all__ = ["__version__"]

import os

from .cli import _abort  # NoReturn

if os.environ.get("ZILANT_CI_IMPORT_HOOK"):
    _abort("Unsafe import before guard!", code=99)  # pragma: no cover

from .utils import root_guard

if not os.environ.get("ZILANT_ALLOW_ROOT") and "PYTEST_CURRENT_TEST" not in os.environ:
    root_guard.assert_safe_or_die()  # pragma: no cover
root_guard.harden_linux()

# Hello, Zilant!
# ZILANT PRIME TEST 12345
