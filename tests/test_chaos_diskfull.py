# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import subprocess
import sys

SCRIPT = os.path.join(os.path.dirname(__file__), "chaos", "disk_full_test.py")


def test_diskfull_script():
    cp = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
    assert cp.returncode == 0
    assert "Traceback" not in cp.stdout
    assert "Traceback" not in cp.stderr
