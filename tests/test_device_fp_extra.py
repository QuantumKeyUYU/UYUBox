from zilant_prime_core.utils import device_fp


def test_read_file_first_line(tmp_path):
    f = tmp_path / "id.txt"
    f.write_text("abc\nextra")
    assert device_fp._read_file_first_line(str(f)) == "abc"


def test_read_file_first_line_missing(tmp_path):
    assert device_fp._read_file_first_line(str(tmp_path / "missing")) == ""
