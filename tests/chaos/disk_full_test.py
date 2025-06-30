#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import tempfile


def main() -> int:
    tmpdir = tempfile.mkdtemp()
    fpath = os.path.join(tmpdir, "fill")
    try:
        with open(fpath, "wb") as f:
            f.write(b"\0" * 1024 * 1024)
    except OSError:
        pass
    print("disk full test completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
