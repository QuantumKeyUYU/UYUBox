try:
    from pythonforandroid.recipe import CffiRecipe
except ImportError:  # pragma: no cover - fallback for newer p4a
    try:
        from pythonforandroid.recipe import PyprojectRecipe as CffiRecipe
    except ImportError:  # pragma: no cover - final fallback
        from pythonforandroid.recipe import PythonRecipe as CffiRecipe


class CryptographyRecipe(CffiRecipe):
    version = "3.4.7"
    url = (
        "https://files.pythonhosted.org/packages/3c/a9/50e54f9b89e0ee1d3f3f94a639a6a39"
        "aea66e68132c0aaf645ed90e2990b/cryptography-3.4.7.tar.gz"
    )
    depends = ["openssl", "setuptools", "cffi"]


recipe = CryptographyRecipe()
