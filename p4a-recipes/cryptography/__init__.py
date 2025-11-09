# p4a-recipes/cryptography/__init__.py

from pythonforandroid.recipe import PythonRecipe


class CryptographyRecipe(PythonRecipe):
    """
    Рецепт для библиотеки cryptography 3.3.2 (последняя без Rust) под python-for-android.

    В requirements указываем диапазон:
        "cryptography<3.4"
    """

    # имя рецепта должно совпадать с именем пакета в requirements
    name = "cryptography"

    # версия, которую собираем
    version = "3.3.2"

    # источник исходников на PyPI
    url = (
        "https://files.pythonhosted.org/packages/source/c/cryptography/"
        "cryptography-{version}.tar.gz"
    )

    # зависимости, которые должны быть собраны до cryptography
    depends = [
        "openssl",
        "cffi",
        "setuptools",
        "six",
        "pycparser",
    ]

    # cryptography нам не нужен в hostpython, только в целевом питоне
    install_in_hostpython = False

    # не вызываем hostpython через targetpython
    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch, **kwargs):
        """
        Дополнительно блокируем попытки использовать Rust,
        даже если когда-нибудь включишь более новую версию.
        Для 3.3.2 это не обязательно, но и не мешает.
        """
        env = super().get_recipe_env(arch, **kwargs)
        env["CRYPTOGRAPHY_DONT_BUILD_RUST"] = "1"
        return env


# объект, который подхватывает p4a
recipe = CryptographyRecipe()
