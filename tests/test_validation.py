import os

from security.validation import (
    collect_issues,
    validate_file_path,
    validate_output_path,
    validate_password,
)


def test_validate_file_path_missing(tmp_path):
    issues = validate_file_path(" ")
    assert issues and issues[0].field == "file_path"

    missing = tmp_path / "missing.bin"
    issues = validate_file_path(str(missing))
    assert issues and "Файл не найден" in issues[0].message


def test_validate_file_path_size_limit(tmp_path):
    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"0" * (2 * 1024 * 1024))
    issues = validate_file_path(str(large_file), max_size_mb=1, must_exist=True)
    assert issues and "1" in issues[0].message


def test_validate_password_complexity():
    weak = validate_password("short")
    assert weak and weak[0].field == "password"

    strong = validate_password("Aa1!complexPWD")
    assert not strong


def test_collect_issues_merges_lists(tmp_path):
    a = validate_file_path(" ")
    b = validate_password("short")
    combined = collect_issues(a, b)
    assert len(combined) == len(a) + len(b)


def test_validate_output_path(tmp_path, monkeypatch):
    missing_dir_target = tmp_path / "missing" / "file.zilant"
    missing_issues = validate_output_path(str(missing_dir_target))
    assert missing_issues and "Каталог" in missing_issues[0].message

    sealed_dir = tmp_path / "sealed"
    sealed_dir.mkdir()
    real_access = os.access

    def fake_access(path, mode):
        if os.path.abspath(path) == os.path.abspath(str(sealed_dir)):
            return False
        return real_access(path, mode)

    monkeypatch.setattr(os, "access", fake_access)
    sealed_target = sealed_dir / "file.zilant"
    perm_issues = validate_output_path(str(sealed_target))
    assert perm_issues and "прав" in perm_issues[0].message

    src = tmp_path / "src.bin"
    src.write_text("data")
    same_path = validate_output_path(str(src), source_path=str(src))
    assert any("совпадает" in issue.message for issue in same_path)

    target = tmp_path / "out.bin"
    ok = validate_output_path(str(target), source_path=str(src))
    assert not ok
