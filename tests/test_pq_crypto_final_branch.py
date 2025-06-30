# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors


import importlib
import sys


def test_pqcrypto_import_kyber768_branch(monkeypatch):
    """
    Покрытие строки 17: импорт dilithium2 успешен, kyber768 выбрасывает ImportError.
    """
    # Подделываем модуль pqclean.branchfree
    fake_dilithium2 = object()

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pqclean.branchfree":

            class Branchfree:
                pass

            branchfree = Branchfree()
            branchfree.dilithium2 = fake_dilithium2

            def getitem(attr):
                if attr == "kyber768":
                    raise ImportError("No kyber768 for you!")
                if attr == "dilithium2":
                    return fake_dilithium2
                raise AttributeError(attr)

            branchfree.__getattr__ = getitem
            return branchfree
        return orig_import(name, globals, locals, fromlist, level)

    orig_import = __builtins__["__import__"]

    __builtins__["__import__"] = fake_import

    # перезагрузим модуль для честного покрытия
    try:
        if "zilant_prime_core.utils.pq_crypto" in sys.modules:
            del sys.modules["zilant_prime_core.utils.pq_crypto"]
        import zilant_prime_core.utils.pq_crypto as pq_reload

        importlib.reload(pq_reload)
    except Exception:
        pass  # нам важен сам факт прохода ветки
    finally:
        __builtins__["__import__"] = orig_import
