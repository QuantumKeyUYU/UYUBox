from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.logger import shprint
from pythonforandroid.toolchain import current_directory
import sh


class CryptographyRecipe(PythonRecipe):
    name = 'cryptography'
    version = '41.0.7'
    url = 'https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-{version}.tar.gz'
    depends = ['openssl', 'cffi', 'setuptools', 'wheel', 'six', 'pycparser']
    call_hostpython_via_targetpython = False

    def install_python_package(self, arch):
        env = self.get_recipe_env(arch)
        hostpython = self.ctx.hostpython

        # ensure pip on hostpython
        try:
            shprint(hostpython, '-m', 'ensurepip', '--upgrade', _env=env)
        except sh.ErrorReturnCode:
            pass
        shprint(hostpython, '-m', 'pip', 'install', '--upgrade', 'pip', 'setuptools', 'wheel', _env=env)

        build_dir = self.get_build_dir(arch.arch)
        site_packages = self.ctx.get_site_packages_dir(arch)

        with current_directory(build_dir):
            shprint(
                hostpython, '-m', 'pip', 'install', '.',
                '--no-deps', '--no-build-isolation',
                '--target', site_packages,
                _env=env
            )


recipe = CryptographyRecipe()
