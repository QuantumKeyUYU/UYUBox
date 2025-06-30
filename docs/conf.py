# docs/conf.py
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

import os
import sys

# Чтобы Sphinx видел пакет
sys.path.insert(0, os.path.abspath("../src"))
os.environ.setdefault("ZILANT_ALLOW_ROOT", "1")

# -- Project information -----------------------------------------------------

project = "Zilant Prime Core"
author = "Zilant Prime Core Contributors"
release = "0.1.0"

# -- General configuration ---------------------------------------------------

CI = os.environ.get("CI") == "true"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx_autodoc_typehints",
    "m2r2",
]
if not CI and "sphinx.ext.intersphinx" not in extensions:
    extensions.append("sphinx.ext.intersphinx")

try:  # optional Mermaid
    pass  # type: ignore
except Exception:  # pragma: no cover - skip if unavailable
    pass
else:
    extensions.append("sphinxcontrib.mermaid")

# Автоматически генерить заглушки для модулей
autosummary_generate = True

# Опции по умолчанию для autodoc
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
}

if not CI:
    intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}
else:  # pragma: no cover - offline
    intersphinx_mapping = {}

# Mermaid (если нужна встроенная диаграмма)
mermaid_cmd = "npx -y @mermaid-js/mermaid-cli"
mermaid_output_format = "png"

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
nitpicky = not CI

# -- HTML output -------------------------------------------------------------

try:  # optional theme
    import furo  # type: ignore  # noqa: F401

    html_theme = "furo"
except Exception:  # pragma: no cover - fallback
    html_theme = "alabaster"
html_static_path = ["_static"]
