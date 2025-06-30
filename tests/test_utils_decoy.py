# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from zilant_prime_core.utils import decoy


def test_generate_decoy_file_creates_file(tmp_path):
    path = tmp_path / "decoy1.zil"
    decoy.generate_decoy_file(path)
    assert path.exists()
    assert path.stat().st_size > 0


def test_is_decoy_file_and_expired(tmp_path):
    path = tmp_path / "decoy2.zil"
    decoy.generate_decoy_file(path)
    assert decoy.is_decoy_file(path)
    assert not decoy.is_decoy_expired(path, max_age=3600)
    # истёк
    path.write_bytes(b"decoydata")
    assert decoy.is_decoy_file(path)
    assert decoy.is_decoy_expired(path, max_age=0)


def test_delete_expired_decoy_files(tmp_path):
    recent = tmp_path / "recent.zil"
    expired = tmp_path / "expired.zil"
    decoy.generate_decoy_file(recent)
    decoy.generate_decoy_file(expired)
    expired.write_bytes(b"old")
    assert recent.exists() and expired.exists()
    deleted = decoy.delete_expired_decoy_files(tmp_path, max_age=0)
    assert expired in deleted or not expired.exists()
    assert recent.exists()


def test_clean_decoy_folder(tmp_path):
    d1 = tmp_path / "d1.zil"
    d2 = tmp_path / "d2.zil"
    non_decoy = tmp_path / "n1.txt"
    decoy.generate_decoy_file(d1)
    decoy.generate_decoy_file(d2)
    non_decoy.write_text("hi")
    decoy.clean_decoy_folder(tmp_path)
    assert not d1.exists() and not d2.exists()
    assert non_decoy.exists()


def test_exceptions_and_logging(tmp_path):
    p = tmp_path / "not_decoy.txt"
    p.write_text("hi")
    decoy.clean_decoy_folder(tmp_path)
    assert p.exists()
    result = decoy.delete_expired_decoy_files(tmp_path / "empty", max_age=0)
    assert result == []


def test_generate_many_and_clean(tmp_path):
    for i in range(10):
        path = tmp_path / f"d_{i}.zil"
        decoy.generate_decoy_file(path)
    decoy.clean_decoy_folder(tmp_path)
    assert all(not (tmp_path / f"d_{i}.zil").exists() for i in range(10))
