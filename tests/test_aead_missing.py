# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from src.aead import decrypt_chacha20_poly1305


def test_decrypt_chacha20_poly1305_nonce_type_error():
    with pytest.raises(TypeError):
        decrypt_chacha20_poly1305(b"x" * 32, "not-bytes", b"cipher", b"tag123456789012")
