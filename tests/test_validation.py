from security.validation import collect_issues, validate_file_path, validate_password


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
    assert issues and "превышает" in issues[0].message


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
