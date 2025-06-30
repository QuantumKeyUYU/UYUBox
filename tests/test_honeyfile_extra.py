# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest
from pathlib import Path

from zilant_prime_core.utils.honeyfile import HoneyfileError, check_tmp_for_honeyfiles, create_honeyfile, is_honeyfile


def test_create_and_detect_honeyfile(tmp_path):
    file = tmp_path / "hfile.txt"
    create_honeyfile(str(file))
    assert is_honeyfile(str(file)) is True


def test_is_honeyfile_false_on_non_honeyfile(tmp_path):
    file = tmp_path / "plain.txt"
    file.write_text("not a honeyfile")
    assert is_honeyfile(str(file)) is False


def test_is_honeyfile_exception(tmp_path, monkeypatch):
    file = tmp_path / "noexist.txt"
    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: (_ for _ in ()).throw(OSError))
    assert is_honeyfile(str(file)) is False


def test_check_tmp_for_honeyfiles_raises(tmp_path):
    file = tmp_path / "honey.txt"
    create_honeyfile(str(file))
    with pytest.raises(HoneyfileError):
        check_tmp_for_honeyfiles(str(tmp_path))


def test_check_tmp_for_honeyfiles_ok(tmp_path):
    file = tmp_path / "plain.txt"
    file.write_text("just text")
    check_tmp_for_honeyfiles(str(tmp_path))


def test_check_tmp_for_honeyfiles_skips_dirs(tmp_path):
    (tmp_path / "subdir").mkdir()
    file = tmp_path / "just.txt"
    file.write_text("no honeyfile")
    check_tmp_for_honeyfiles(str(tmp_path))
