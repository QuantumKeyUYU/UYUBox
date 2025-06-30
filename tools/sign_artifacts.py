#!/usr/bin/env python3
"""
Простейшая «подпись» артефактов: считаем SHA‑256 и кладём *.sha256 рядом.
Настоящую cryptographic signature можно прикрутить позже (cosign, gpg, …).
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ARTIFACTS_DIR = Path("dist")
if not ARTIFACTS_DIR.exists():
    sys.exit("❌  nothing to sign (dist/ missing)")

for file in ARTIFACTS_DIR.iterdir():
    if file.is_file():
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        sig_path = file.with_suffix(file.suffix + ".sha256")
        sig_path.write_text(f"{digest}  {file.name}\n")
        print("🔏", sig_path)
print("✅  all artifacts signed")
