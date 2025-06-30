from zilant_prime_core.utils.counter import BACKUP_COUNTER_FILE, COUNTER_FILE, read_counter, write_counter


def test_write_creates_files(tmp_path, monkeypatch):
    monkeypatch.setattr("zilant_prime_core.utils.counter.COUNTER_FILE", tmp_path / "c.txt")
    monkeypatch.setattr("zilant_prime_core.utils.counter.BACKUP_COUNTER_FILE", tmp_path / "b.txt")
    globals()["COUNTER_FILE"] = tmp_path / "c.txt"
    globals()["BACKUP_COUNTER_FILE"] = tmp_path / "b.txt"
    write_counter(3)
    assert COUNTER_FILE.read_text().strip() == "3"
    assert BACKUP_COUNTER_FILE.read_text().strip() == "3"
    assert read_counter() == 3
