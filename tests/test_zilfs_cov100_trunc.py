import importlib


def test_truncate_file_for_coverage(tmp_path):
    zilfs = importlib.import_module("src.zilant_prime_core.zilfs")
    file = tmp_path / "zzz.txt"
    file.write_bytes(b"abcdef")
    zilfs._truncate_file(file, 2)
    assert file.read_bytes() == b"ab"
