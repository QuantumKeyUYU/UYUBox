# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

# ----------------------- paths / tools -----------------------------
SPHINXBUILD   ?= sphinx-build
SPHINXOPTS    ?=
SOURCEDIR     ?= .
BUILDDIR      ?= _build

MERMAID       ?= npx -y @mermaid-js/mermaid-cli
DIAGRAM_SRC    = architecture/key_lifecycle.mmd
DIAGRAM_OUT    = _static/key_lifecycle.svg

.PHONY: help clean mermaid html

help:
	@echo "make mermaid   – обновить все *.mmd → SVG"
	@echo "make html      – полная сборка HTML (вызывает mermaid)"
	@echo "make clean     – стереть $(BUILDDIR) и сгенерённые SVG"

# ----------------------- mermaid diagrams --------------------------
$(DIAGRAM_OUT): $(DIAGRAM_SRC)
	$(MERMAID) -i $< -o $@

mermaid: $(DIAGRAM_OUT)

# ----------------------- Sphinx build ------------------------------
html: mermaid
	$(SPHINXBUILD) -M html $(SOURCEDIR) $(BUILDDIR) $(SPHINXOPTS)

clean:
	rm -rf $(BUILDDIR) $(DIAGRAM_OUT)
