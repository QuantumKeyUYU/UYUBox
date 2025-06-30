# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import os
import pytest
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

sys.modules.setdefault("yaml", ModuleType("yaml"))
sys.modules.setdefault("requests", ModuleType("requests"))
crypto_module = ModuleType("cryptography")
hazmat_module = ModuleType("cryptography.hazmat")
primitives_module = ModuleType("cryptography.hazmat.primitives")
ciphers_module = ModuleType("cryptography.hazmat.primitives.ciphers")
aead_module = ModuleType("cryptography.hazmat.primitives.ciphers.aead")


class AESGCM:
    def __init__(self, *a, **k) -> None:
        pass

    def encrypt(self, *a, **k) -> bytes:
        return b""

    def decrypt(self, *a, **k) -> bytes:
        return b""


aead_module.AESGCM = AESGCM
ciphers_module.aead = aead_module
primitives_module.ciphers = ciphers_module
hazmat_module.primitives = primitives_module
crypto_module.hazmat = hazmat_module
sys.modules.setdefault("cryptography", crypto_module)
sys.modules.setdefault("cryptography.hazmat", hazmat_module)
sys.modules.setdefault("cryptography.hazmat.primitives", primitives_module)
sys.modules.setdefault("cryptography.hazmat.primitives.ciphers", ciphers_module)
sys.modules.setdefault(
    "cryptography.hazmat.primitives.ciphers.aead",
    aead_module,
)

# Provide minimal stub package structure to import honeyfile without heavy
# dependencies.
pkg = ModuleType("zilant_prime_core")
pkg.__path__ = [str(Path(__file__).resolve().parents[1] / "src" / "zilant_prime_core")]
utils_pkg = ModuleType("zilant_prime_core.utils")
utils_pkg.__path__ = [str(Path(__file__).resolve().parents[1] / "src" / "zilant_prime_core" / "utils")]
cli_pkg = ModuleType("zilant_prime_core.cli")
cli_pkg._abort = lambda *a, **k: None
root_guard_mod = ModuleType("zilant_prime_core.utils.root_guard")
root_guard_mod.assert_safe_or_die = lambda: None
root_guard_mod.harden_linux = lambda: None
utils_pkg.root_guard = root_guard_mod
pkg.utils = utils_pkg
sys.modules.setdefault("zilant_prime_core", pkg)
sys.modules.setdefault("zilant_prime_core.cli", cli_pkg)
sys.modules.setdefault("zilant_prime_core.utils", utils_pkg)
sys.modules.setdefault("zilant_prime_core.utils.root_guard", root_guard_mod)

from zilant_prime_core.utils.honeyfile import (
    HoneyfileError,
    HoneyfileManager,
    check_tmp_for_honeyfiles,
    create_honeyfile,
    is_honeyfile,
)


def test_detect_honeyfile(tmp_path):
    f = tmp_path / "secret.doc"
    # Создаём honeyfile с маркером!
    create_honeyfile(str(f))
    assert is_honeyfile(str(f))
    # Проверка на выброс исключения:
    with pytest.raises(HoneyfileError):
        check_tmp_for_honeyfiles(str(tmp_path))


def test_manager_create_honeyfile(tmp_path):
    manager = HoneyfileManager()
    dest = manager.create_honeyfile(tmp_path, "bait.txt")
    assert dest.exists()


def test_manager_check_for_access(tmp_path):
    manager = HoneyfileManager()
    dest = manager.create_honeyfile(tmp_path, "bait.txt")
    atime = dest.stat().st_atime
    with patch("zilant_prime_core.utils.honeyfile.Notifier.notify") as notify:
        os.utime(dest, (atime + 5, dest.stat().st_mtime))
        manager.check_for_access()
        notify.assert_called_once()


def test_manager_missing_file(tmp_path):
    manager = HoneyfileManager()
    dest = manager.create_honeyfile(tmp_path, "bait.txt")
    dest.unlink()
    with patch("zilant_prime_core.utils.honeyfile.Notifier.notify") as notify:
        manager.check_for_access()
        notify.assert_not_called()
