# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

from setuptools import find_packages, setup

setup(
    name="uyubox",
    version="0.1.0",
    description="UYUBox — локальное приложение на основе Zilant Prime Core",
    author="Ваша команда",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[
        "click<9.0,>=8.1",
        "cryptography<43.0,>=38.0.4",
        "argon2-cffi<24.0,>=23.1",
        "hvac<3.0,>=2.3",
        "flask<3.0,>=2.2",
        "prometheus-client<1.0,>=0.16.0",
        "shamir>=0.1",
        "pynacl<2.0,>=1.5",
        "boto3<2.0,>=1.28",
        "PyYAML<7.0,>=6.0",
        "zstandard>=0.23.0",
        "tqdm>=4.66.0",
        "psutil>=5.9.0",
        "requests<3.0,>=2.32",
        "PySide6<7.0,>=6.9.1",
        # dev / тестирование
        "pytest>=8.0.0",
        "pytest-cov>=5.0.0",
        "pytest-timeout>=2.3.0",
        "pytest-xdist>=3.5.0",
        "hypothesis>=6.0.0",
        # линтеры и форматтеры
        "ruff>=0.2.0",
        "black>=23.1.0",
        "isort>=5.10.1",
        "mypy>=1.8.0",
        # безопасность
        "bandit>=1.7.0",
        "semgrep>=1.18.0",
        "reuse>=2.1.0",
        # остальное
        "filelock>=3.13.0",
        "pre-commit>=2.20.0",
    ],
    entry_points={
        "console_scripts": [
            "uyubox=zilant_prime_core.cli:main",
            "uyubox-gui=uyubox_gui.main:main",
        ],
    },
)
