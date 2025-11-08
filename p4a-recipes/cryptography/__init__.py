from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.logger import shprint, info
from pythonforandroid.toolchain import current_directory
import sh


class CryptographyRecipe(PythonRecipe):
    """
    Рецепт cryptography 3.4.7 (без Rust) для нового API python-for-android.

    - Ставим через hostpython+pip прямо в site-packages таргета.
    - Не используем call_hostpython_via_targetpython.
    """

    name = "cryptography"
    version = "3.4.7"
    url = (
        "https://files.pythonhosted.org/packages/source/c/cryptography/"
        "cryptography-{version}.tar.gz"
    )

    # ВАЖНО: это список, а не tuple — p4a в __init__ делает depends.append('python3')
    depends = [
        "openssl",
        "cffi",
        "setuptools",
        "wheel",
        "six",
        "pycparser",
    ]

    # Не прогонять hostpython через targetpython
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        env = self.get_recipe_env(arch)
        hostpython = self.ctx.hostpython

        # 1. Убедиться, что у hostpython есть рабочий pip + базовые билдеры
        try:
            shprint(hostpython, "-m", "ensurepip", "--upgrade", _env=env)
        except (sh.ErrorReturnCode, OSError):
            info("ensurepip недоступен или упал, продолжаем с существующим pip")

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

        # 2. Установить сам cryptography в site-packages таргетного Python
        build_dir = self.get_build_dir(arch.arch)
        site_packages = self.ctx.get_site_packages_dir(arch)

        with current_directory(build_dir):
            shprint(
                hostpython,
                "-m",
                "pip",
                "install",
                ".",
                "--no-deps",            # зависимости уже собраны по depends
                "--no-build-isolation", # не тащим современный build backend
                "--target",
                site_packages,
                _env=env,
            )


recipe = CryptographyRecipe()
