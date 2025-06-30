#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import signal
import subprocess
import sys
import time


def main() -> int:
    if hasattr(os, "fork"):
        pid = os.fork()
        if pid == 0:
            while True:
                time.sleep(1)
        else:
            time.sleep(0.5)
            os.kill(pid, signal.SIGSTOP)
            time.sleep(0.5)
            os.kill(pid, signal.SIGKILL)
    else:
        subprocess.run([sys.executable, "-c", "import time; time.sleep(0.1)"], check=True)
    print("sigstop test completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
