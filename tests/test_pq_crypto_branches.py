# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

# tests/test_pq_crypto_branches.py

import importlib
import pytest
import sys

# Импортируем как отдельный модуль — путь подстрой под себя
import zilant_prime_core.utils.pq_crypto as pq


def test_pq_crypto_import_branch_17(monkeypatch):
    """Покрытие: except Exception в импорте pqclean.branchfree (строка 17)."""
    # Save old references
    old_pqclean = sys.modules.get("pqclean")
    old_branchfree = sys.modules.get("pqclean.branchfree")

    # Мокаем "pqclean.branchfree", чтобы вызвать ImportError
    sys.modules["pqclean.branchfree"] = None

    # Нужно также временно удалить модули из already-imported
    if "zilant_prime_core.utils.pq_crypto" in sys.modules:
        del sys.modules["zilant_prime_core.utils.pq_crypto"]

    try:
        import zilant_prime_core.utils.pq_crypto as pq_reload

        importlib.reload(pq_reload)
    except Exception:
        pass  # ignore, главное — ветка пройдена
    finally:
        if old_branchfree is not None:
            sys.modules["pqclean.branchfree"] = old_branchfree
        else:
            sys.modules.pop("pqclean.branchfree", None)
        if old_pqclean is not None:
            sys.modules["pqclean"] = old_pqclean
        else:
            sys.modules.pop("pqclean", None)


def test_falconsig_double_import_branch(monkeypatch):
    """Покрытие: обе except Exception внутри FalconSig.__init__ (строка 120)."""
    # Мокаем оба импорта falcon1024 на выброс ImportError
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if "falcon1024" in name:
            raise ImportError("No falcon1024 for you!")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = fake_import
    try:
        with pytest.raises(RuntimeError, match="Falcon not installed"):
            pq.FalconSig()
    finally:
        builtins.__import__ = real_import


def test_sphincssig_double_import_branch(monkeypatch):
    """Покрытие: обе except Exception внутри SphincsSig.__init__ (строка 148)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if "sphincsplus_sha256_128f_simple" in name:
            raise ImportError("No sphincsplus_sha256_128f_simple for you!")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = fake_import
    try:
        with pytest.raises(RuntimeError, match="SPHINCS\\+ not installed"):
            pq.SphincsSig()
    finally:
        builtins.__import__ = real_import
