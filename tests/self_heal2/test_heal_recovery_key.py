import hashlib

from container import get_metadata, pack_file
from zilant_prime_core.self_heal.heal import heal_container


def test_heal_recovery_key(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("hi")
    cont = tmp_path / "a.zil"
    key = b"k" * 32
    pack_file(src, cont, key)

    blob = cont.read_bytes()
    sep = blob.find(b"\n\n")
    cont.write_bytes(blob[: sep + 5])
    seed = hashlib.sha3_256(cont.read_bytes()).digest()
    assert heal_container(cont, key, rng_seed=seed)
    meta = get_metadata(cont)
    assert "recovery_key_hex" in meta
