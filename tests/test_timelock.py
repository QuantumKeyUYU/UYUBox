from click.testing import CliRunner

from timelock import lock_file, unlock_file
from zilant_prime_core.cli import cli


def test_lock_unlock(tmp_path, monkeypatch):
    src = tmp_path / "plain.txt"
    src.write_text("hello")
    locked = tmp_path / "locked.bin"
    unlocked = tmp_path / "out.txt"

    monkeypatch.setattr("timelock.generate_proof", lambda delay, data: b"p" * 8)
    monkeypatch.setattr("timelock.verify_proof", lambda proof, data: True)

    lock_file(src, locked, 10)
    unlock_file(locked, unlocked)
    assert unlocked.read_text() == "hello"


def test_cli_timelock(tmp_path, monkeypatch):
    src = tmp_path / "f.txt"
    src.write_text("hi")
    locked = tmp_path / "f.lock"
    unlocked = tmp_path / "f.out"
    monkeypatch.setattr("timelock.generate_proof", lambda delay, data: b"p" * 8)
    monkeypatch.setattr("timelock.verify_proof", lambda proof, data: True)
    runner = CliRunner()
    res1 = runner.invoke(
        cli,
        ["timelock", "lock", "--delay", "5", "--in-file", str(src), "--out-file", str(locked)],
    )
    assert res1.exit_code == 0
    res2 = runner.invoke(
        cli,
        ["timelock", "unlock", "--in-file", str(locked), "--out-file", str(unlocked)],
    )
    assert res2.exit_code == 0
    assert unlocked.read_text() == "hi"
