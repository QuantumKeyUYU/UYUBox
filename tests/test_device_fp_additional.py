# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

from zilant_prime_core.utils.device_fp import SALT_CONST, _read_file_first_line


def test_salt_length():
    assert len(SALT_CONST) == 16


def test_read_file_first_line_empty(tmp_path):
    p = tmp_path / "no.txt"
    assert _read_file_first_line(str(p)) == ""
