# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_metadata_optional_extra.py

from src.zilant_prime_core.container.metadata import Metadata


def test_metadata_default_extra_not_none():
    m = Metadata(file="a", size=1)
    # extra всегда dict, даже если не передавали
    assert isinstance(m.extra, dict)
