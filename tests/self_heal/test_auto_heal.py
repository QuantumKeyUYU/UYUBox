import os

from zilant_prime_core.self_heal.reaction import maybe_self_destruct, record_event, rotate_key


def test_rotate_and_record(tmp_path):
    old = b"k" * 32
    new = rotate_key(old)
    assert isinstance(new, bytes)
    log = tmp_path / "self_heal.log"
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        record_event({"msg": "hi"})
    finally:
        os.chdir(cwd)
    assert log.exists()


def test_maybe_self_destruct(tmp_path):
    p = tmp_path / "x"
    p.write_text("data")
    os.environ["ZILANT_SELF_DESTRUCT"] = "1"
    maybe_self_destruct(p)
    assert not p.exists()
