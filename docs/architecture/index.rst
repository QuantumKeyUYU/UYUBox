# docs/architecture/index.rst
Architecture Overview
=====================

.. image:: /_static/key_lifecycle.svg
   :alt: Key lifecycle diagram

This document describes the high-level architecture of Zilant Prime Core.

Sections
--------

- **Key Lifecycle**: how cryptographic keys are generated, stored, and retired.
- **Component Interaction**: how CLI, AEAD core, containers, and watchdog collaborate.
- **Extension Points**: where to plug in custom backends (e.g., IPFS).
