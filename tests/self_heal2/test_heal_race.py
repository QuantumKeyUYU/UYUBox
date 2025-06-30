import hashlib
import threading

from container import pack_file
from zilant_prime_core.self_heal.heal import heal_container


def test_heal_race(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("data")
    cont = tmp_path / "f.zil"
    key = b"k" * 32
    pack_file(src, cont, key)

    blob = cont.read_bytes()
    sep = blob.find(b"\n\n")
    cont.write_bytes(blob[: sep + 5])
    seed = hashlib.sha3_256(cont.read_bytes()).digest()

    results: list[bool | None] = [None, None]

    def worker(idx: int) -> None:
        results[idx] = heal_container(cont, key, rng_seed=seed)

    t1 = threading.Thread(target=worker, args=(0,))
    t2 = threading.Thread(target=worker, args=(1,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert sorted(results) == [False, True]
