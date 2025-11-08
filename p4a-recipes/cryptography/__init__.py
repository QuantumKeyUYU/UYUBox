from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.logger import shprint, info
from pythonforandroid.toolchain import current_directory
import sh


class CryptographyRecipe(PythonRecipe):
    """
    Cryptography 3.4.7 (без Rust) с современным API p4a.
    Ставим через hostpython+pip прямо в site-packages таргета.
    """
    version = '3.4.7'
    url = 'https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-{version}.tar.gz'
    name = 'cryptography'

    # зависимости для сборки без Rust
    depends = ('openssl', 'cffi', 'setuptools', 'wheel', 'six', 'pycparser')

    # p4a: не прокидывать hostpython через targetpython
    call_hostpython_via_targetpython = False

    # основной шаг сборки/установки
    def build_arch(self, arch):
        # окружение для сборки и инструменты
        env = self.get_recipe_env(arch)
        hostpython = self.ctx.hostpython

        # 1) Убедиться, что у hostpython есть pip + свежие setuptools/wheel
        try:
            shprint(hostpython, '-m', 'ensurepip', '--upgrade', _env=env)
        except sh.ErrorReturnCode:
            # бывает, что ensurepip недоступен — ок
            pass

        try:
            shprint(hostpython, '-m', 'pip', 'install', '--upgrade',
                    'pip', 'setuptools', 'wheel', _env=env)
        except sh.ErrorReturnCode:
            # на некоторых ранне-собранных hostpython pip может уже быть ок
            info('pip/bootstrap upgrade step failed or skipped; continuing')

        # 2) Устанавливаем сам пакет в site-packages таргета
        build_dir = self.get_build_dir(arch.arch)
        site_packages = self.ctx.get_site_packages_dir(arch)

        with current_directory(build_dir):
            # используем --no-build-isolation, чтобы не тянуть современный build backend
            # и --target, чтобы ставить прямо в директорию таргета
            shprint(hostpython, '-m', 'pip', 'install', '.',
                    '--no-build-isolation',
                    '--no-deps',  # зависимости p4a уже даст через depends
                    '--target', site_packages,
                    _env=env)


recipe = CryptographyRecipe()
