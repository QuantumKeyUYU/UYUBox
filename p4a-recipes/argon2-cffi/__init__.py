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


def _move_contents(src_dir: str, dst_dir: str) -> None:
    """Move all entries from ``src_dir`` into ``dst_dir``.

    The python-for-android ``PythonRecipe`` expects the unpacked sources to
    live directly inside the recipe build directory.  The argon2-cffi sdist
    however extracts into a versioned folder (``argon2-cffi-21.3.0``), so we
    reshuffle the files to match the expected layout.
    """

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
            return

        extracted_dir = os.path.join(build_dir, f"argon2-cffi-{self.version}")
        if not os.path.isdir(extracted_dir):
            return

        _move_contents(extracted_dir, build_dir)
        shutil.rmtree(extracted_dir)


recipe = Argon2CFFIRecipe()
