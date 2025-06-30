# tests/test_formats.py
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import pytest

from zilant_prime_core.utils.formats import from_b64, from_hex, to_b64, to_hex


def test_to_hex_valid():
    assert to_hex(b"\x01\x02\xff") == "0102ff"


def test_to_hex_invalid_type():
    with pytest.raises(TypeError) as exc:
        to_hex("not-bytes")  # type: ignore
    assert "to_hex expects bytes" in str(exc.value)


def test_from_hex_valid():
    assert from_hex("a1b2") == bytes.fromhex("a1b2")


def test_from_hex_invalid_type():
    with pytest.raises(TypeError) as exc:
        from_hex(b"0102")  # type: ignore
    assert "from_hex expects str" in str(exc.value)


def test_from_hex_invalid_value():
    with pytest.raises(ValueError) as exc:
        from_hex("zzzz")
    assert "Invalid hex" in str(exc.value)


def test_to_b64_valid():
    assert to_b64(b"\x00\xff") == "AP8="


def test_to_b64_invalid_type():
    with pytest.raises(TypeError) as exc:
        to_b64("not-bytes")  # type: ignore
    assert "to_b64 expects bytes" in str(exc.value)


def test_from_b64_valid():
    assert from_b64("AP8=") == b"\x00\xff"


def test_from_b64_invalid_type():
    with pytest.raises(TypeError) as exc:
        from_b64(b"AP8=")  # type: ignore
    assert "from_b64 expects str" in str(exc.value)


def test_from_b64_invalid_value():
    with pytest.raises(ValueError) as exc:
        from_b64("!!!")
    assert "Invalid base64" in str(exc.value)
