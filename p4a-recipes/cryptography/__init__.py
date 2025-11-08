from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.logger import shprint
from pythonforandroid.toolchain import current_directory
import sh


class CryptographyRecipe(PythonRecipe):
    # версия без Rust
    version = "3.4.7"
    url = "https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-{version}.tar.gz"

    # зависимости времени сборки/линковки
    depends = ["openssl", "cffi", "setuptools", "six", "pycparser"]

    # p4a по умолчанию зовёт `setup.py install`. Нам нужно заранее
    # убедиться, что в hostpython есть pip/setuptools/wheel.
    def install_python_package(self, arch):
        env = self.get_recipe_env(arch)
        hostpython = sh.Command(self.ctx.hostpython)

        # 1) bootstrap pip для hostpython (некоторые сборки идут без pip)
        try:
            shprint(hostpython, "-m", "ensurepip", _env=env)
        except sh.ErrorReturnCode:
            # ignore: если уже установлен
            pass

        # 2) обновить pip + поставить setuptools/wheel в hostpython
        shprint(
            hostpython,
            "-m",
            "pip",
            "install",
            "-U",
            "pip",
            "setuptools",
            "wheel",
            _env=env,
        )

        # 3) стандартная установка пакета (в таргетный site-packages)
        build_dir = self.get_build_dir(arch.arch)
        site_packages_dir = self.ctx.get_site_packages_dir(arch)

        with current_directory(build_dir):
            self.call_hostpython_via_targetpython(
                "setup.py",
                "install",
                "-O2",
                f"--root={site_packages_dir}",
                "--install-lib=.",
                _env=env,
            )


recipe = CryptographyRecipe()
