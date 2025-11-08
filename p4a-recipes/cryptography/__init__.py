try:
    from pythonforandroid.recipe import CffiRecipe
except ImportError:  # pragma: no cover - fallback for newer p4a
    try:
        from pythonforandroid.recipe import PyprojectRecipe as CffiRecipe
    except ImportError:  # pragma: no cover - final fallback
        from pythonforandroid.recipe import PythonRecipe as CffiRecipe

from pythonforandroid.logger import shprint


class CryptographyRecipe(CffiRecipe):
    version = "3.4.7"
    # The previously pinned wheel URL used a hashed PyPI storage path which is
    # no longer available (404).  Using the canonical ``packages/source`` path
    # keeps the recipe resilient to future storage migrations on PyPI while
    # still referencing the exact same release archive.
    url = "https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-3.4.7.tar.gz"
    depends = ["openssl", "setuptools", "cffi"]

    def prebuild_arch(self, arch):
        super().prebuild_arch(arch)

        hostpython = getattr(self.ctx, "hostpython", None)
        if hostpython is None:
            return

        # ``ensurepip`` is not guaranteed to install ``setuptools`` when
        # python-for-android builds the hostpython.  In GitHub Actions the
        # resulting environment was missing ``setuptools`` which caused the
        # cryptography recipe installation to abort with ``ModuleNotFoundError``.
        #
        # First bootstrap ``pip`` (if possible) and then ensure that
        # ``setuptools`` and ``wheel`` are available to satisfy
        # ``setup.py``-based packages such as ``cryptography``.
        shprint(hostpython, "-m", "ensurepip", "--upgrade")
        shprint(
            hostpython,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "pip",
            "setuptools",
            "wheel",
        )


recipe = CryptographyRecipe()
