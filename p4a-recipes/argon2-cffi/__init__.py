# Custom python-for-android recipe for argon2-cffi 21.3.0.
#
# Git-тег 21.3.0 на GitHub отсутствует, релиз есть только как sdist-tarball.
# Поэтому тянем исходники с PyPI и раскладываем содержимое на уровень build_dir,
# чтобы PythonRecipe нашёл setup.py там, где ожидает.

import os
import shutil
from pythonforandroid.recipe import PythonRecipe


def _move_contents(src_dir: str, dst_dir: str) -> None:
    """Переместить всё из src_dir в dst_dir, перезаписывая при необходимости."""
    for entry in os.listdir(src_dir):
        src_path = os.path.join(src_dir, entry)
        dst_path = os.path.join(dst_dir, entry)

        if os.path.exists(dst_path):
            if os.path.isdir(dst_path):
                shutil.rmtree(dst_path)
            else:
                os.remove(dst_path)

        shutil.move(src_path, dst_path)


class Argon2CFFIRecipe(PythonRecipe):
    """Build argon2-cffi 21.3.0 from the PyPI sdist."""

    name = "argon2-cffi"
    version = "21.3.0"
    url = (
        "https://files.pythonhosted.org/packages/source/a/argon2-cffi/"
        "argon2-cffi-{version}.tar.gz"
    )
    depends = ["cffi", "setuptools", "six", "pycparser"]
    install_in_hostpython = False
    call_hostpython_via_targetpython = False

    def prebuild_arch(self, arch):
        super().prebuild_arch(arch)

        build_dir = self.get_build_dir(arch.arch)
        setup_py = os.path.join(build_dir, "setup.py")
        if os.path.exists(setup_py):
            return  # Уже разложено как надо

        extracted_dir = os.path.join(build_dir, f"argon2-cffi-{self.version}")
        if not os.path.isdir(extracted_dir):
            return  # На этом этапе ещё нечего перекладывать

        _move_contents(extracted_dir, build_dir)
        shutil.rmtree(extracted_dir)


recipe = Argon2CFFIRecipe()
