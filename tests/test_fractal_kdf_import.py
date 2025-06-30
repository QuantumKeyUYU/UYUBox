import importlib
from types import ModuleType


def test_fractal_kdf_fallback(monkeypatch) -> None:
    """
    При отсутствии переменной среды BLAKE3_IMPL модуль
    все равно должен импортироваться без ошибок.
    """
    monkeypatch.delenv("BLAKE3_IMPL", raising=False)

    # перезагружаем модуль, чтобы отработала ветка без BLAKE3
    if "zilant_prime_core.crypto.fractal_kdf" in globals():
        del globals()["zilant_prime_core.crypto.fractal_kdf"]

    mod: ModuleType = importlib.import_module("zilant_prime_core.crypto.fractal_kdf")
    assert hasattr(mod, "fractal_kdf")
