"""Custom python-for-android recipe for argon2-cffi 21.3.0.

The upstream python-for-android recipe fetches the sources via git and
attempts to checkout a tag named ``21.3.0``.  GitHub only provides this
release as an sdist tarball, so the checkout step fails during CI builds
(
``ErrorReturnCode_1: /usr/bin/git checkout 21.3.0``).  This recipe mirrors
the stock behaviour but pulls the source archive from PyPI instead of git,
which allows Buildozer to resolve the dependency reliably.
"""

import os
import shutil

from pythonforandroid.recipe import PythonRecipe


def _flatten_sdist(build_dir: str, version: str) -> None:
    """Ensure ``build_dir`` contains the unpacked sources directly.

    The argon2-cffi sdist expands into a versioned subdirectory
    (``argon2-cffi-21.3.0``).  python-for-android expects ``setup.py`` to live
    at the root of ``build_dir`` though, so we move the extracted files up one
    level when necessary.
    """

    setup_py = os.path.join(build_dir, "setup.py")
    if os.path.exists(setup_py):
        return

    extracted_dir = os.path.join(build_dir, f"argon2-cffi-{version}")
    if not os.path.isdir(extracted_dir):
        return

    for entry in os.listdir(extracted_dir):
        src_path = os.path.join(extracted_dir, entry)
        dst_path = os.path.join(build_dir, entry)

        if os.path.exists(dst_path):
            if os.path.isdir(dst_path):
                shutil.rmtree(dst_path)
            else:
                os.remove(dst_path)

        shutil.move(src_path, dst_path)

    shutil.rmtree(extracted_dir)



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
        _flatten_sdist(self.get_build_dir(arch.arch), self.version)

    def build_arch(self, arch):
        _flatten_sdist(self.get_build_dir(arch.arch), self.version)
        super().build_arch(arch)


recipe = Argon2CFFIRecipe()
