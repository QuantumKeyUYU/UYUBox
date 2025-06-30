import hashlib

from container import pack_file
from zilant_prime_core.crypto.fractal_kdf import fractal_kdf
from zilant_prime_core.self_heal.heal import SelfHealFrozen, heal_container


def test_heal_limit_freeze(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("data")
    cont = tmp_path / "f.zil"
    key = b"k" * 32
    pack_file(src, cont, key)

    cur_key = key
    for _ in range(3):
        blob = cont.read_bytes()
        sep = blob.find(b"\n\n")
        truncated = blob[: sep + 5]
        cont.write_bytes(truncated)
        seed = hashlib.sha3_256(truncated).digest()
        assert heal_container(cont, cur_key, rng_seed=seed)
        cur_key = fractal_kdf(seed)

    blob = cont.read_bytes()
    sep = blob.find(b"\n\n")
    truncated = blob[: sep + 5]
    cont.write_bytes(truncated)
    seed = hashlib.sha3_256(truncated).digest()
    try:
        heal_container(cont, cur_key, rng_seed=seed)
    except SelfHealFrozen:
        pass
    else:
        raise AssertionError("expected freeze")
