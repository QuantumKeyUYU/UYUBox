from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.logger import shprint, info
from pythonforandroid.toolchain import current_directory
import sh


class CryptographyRecipe(PythonRecipe):
    """
    Рецепт cryptography 3.4.7 (без Rust) для нового python-for-android.

    - Ставим через hostpython+pip в site-packages таргета.
    - Не используем call_hostpython_via_targetpython.
    """

    name = "cryptography"
    version = "3.4.7"
    url = (
        "https://files.pythonhosted.org/packages/source/c/cryptography/"
        "cryptography-{version}.tar.gz"
    )

    # СПИСОК, а не tuple: p4a в базовом __init__ делает depends.append("python3")
    depends = [
        "openssl",
        "cffi",
        "setuptools",
        "wheel",
        "six",
        "pycparser",
    ]

    # хостовый python вызываем напрямую
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        env = self.get_recipe_env(arch)

        # hostpython как команда, а не строка
        hostpython = sh.Command(self.ctx.hostpython)

        # Попробуем мягко убедиться, что pip живой и, по возможности, свежий
        try:
            shprint(hostpython, "-m", "pip", "--version", _env=env)
            try:
                shprint(
                    hostpython,
                    "-m",
                    "pip",
                    "install",
                    "--upgrade",
                    "pip",
                    "setuptools",
                    "wheel",
                    _env=env,
                )
            except sh.ErrorReturnCode:
                info("Не удалось обновить pip/setuptools/wheel, продолжаем как есть")
        except sh.ErrorReturnCode:
            info("pip для hostpython не найден или не работает, пробуем дальше вслепую")

        # Директория исходников рецепта под конкретную arch
        build_dir = self.get_build_dir(arch.arch)
        # site-packages таргетного питона
        site_packages = self.ctx.get_site_packages_dir(arch)

        # Установка cryptography в site-packages таргета
        with current_directory(build_dir):
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                ".",
                "--no-deps",            # зависимости уже собираются p4a по depends
                "--no-build-isolation", # не тянем современный build backend
                "--target",
                site_packages,
                _env=env,
            )


recipe = CryptographyRecipe()
