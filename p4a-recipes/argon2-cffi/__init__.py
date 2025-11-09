"""Custom python-for-android recipe for argon2-cffi 21.3.0.

The upstream python-for-android recipe fetches the sources via git and
attempts to checkout a tag named ``21.3.0``.  GitHub only provides this
release as an sdist tarball, so the checkout step fails during CI builds
(
``ErrorReturnCode_1: /usr/bin/git checkout 21.3.0``).  This recipe mirrors
the stock behaviour but pulls the source archive from PyPI instead of git,
which allows Buildozer to resolve the dependency reliably.
"""

from pythonforandroid.recipe import PythonRecipe


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


recipe = Argon2CFFIRecipe()
