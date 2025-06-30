from zilant_prime_core.utils.device_fp import device_fp_v2


def test_fp_v2_changes_with_input(monkeypatch):
    def fake_read(path: str) -> str:
        return path

    monkeypatch.setattr("zilant_prime_core.utils.device_fp._read_file_first_line", fake_read)
    fp1 = device_fp_v2()
    monkeypatch.setattr("zilant_prime_core.utils.device_fp._read_file_first_line", lambda p: p + "x")
    fp2 = device_fp_v2()
    assert fp1 != fp2 and len(fp1) == 32
