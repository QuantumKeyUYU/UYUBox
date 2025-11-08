from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.logger import shprint, info
from pythonforandroid.toolchain import current_directory
import sh


class CryptographyRecipe(PythonRecipe):
    """
    Cryptography 3.4.7 (без Rust) c современным API p4a.
    Устанавливаем через hostpython+pip прямо в site-packages таргета.
    """
    name = 'cryptography'
    version = '3.4.7'
    url = 'https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-{version}.tar.gz'

    # зависимости для сборки без Rust
    depends = ('openssl', 'cffi', 'setuptools', 'wheel', 'six', 'pycparser')

    # не прокидывать hostpython через targetpython
    call_hostpython_via_targetpython = False

    def build_arch(self, arch):
        env = self.get_recipe_env(arch)
        hostpython = self.ctx.hostpython

        # 1) гарантируем pip и базовые билдеры у hostpython
        try:
            shprint(hostpython, '-m', 'ensurepip', '--upgrade', _env=env)
        except sh.ErrorReturnCode:
            pass
        try:
            shprint(hostpython, '-m', 'pip', 'install', '--upgrade',
                    'pip', 'setuptools', 'wheel', _env=env)
        except sh.ErrorReturnCode:
            info('pip/setuptools/wheel upgrade skipped')

        # 2) ставим сам пакет в site-packages таргета
        build_dir = self.get_build_dir(arch.arch)
        site_packages = self.ctx.get_site_packages_dir(arch)

        with current_directory(build_dir):
            shprint(hostpython, '-m', 'pip', 'install', '.',
                    '--no-deps', '--no-build-isolation',
                    '--target', site_packages,
                    _env=env)


recipe = CryptographyRecipe()
