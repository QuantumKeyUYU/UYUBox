from pythonforandroid.recipe import CffiRecipe


class CryptographyRecipe(CffiRecipe):
    version = "3.4.7"
    url = (
        "https://files.pythonhosted.org/packages/3c/a9/50e54f9b89e0ee1d3f3f94a639a6a39"
        "aea66e68132c0aaf645ed90e2990b/cryptography-3.4.7.tar.gz"
    )
    depends = ["openssl", "setuptools", "cffi"]


recipe = CryptographyRecipe()
