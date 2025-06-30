import time

from zilant_prime_core.utils.hash_challenge import generate_daily_challenge


def test_generate_daily_challenge(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(time, "strftime", lambda fmt: "2025-01-01")
    challenge = generate_daily_challenge()
    path = tmp_path / ".zilant" / "challenge_db"
    assert path.read_text() == challenge
