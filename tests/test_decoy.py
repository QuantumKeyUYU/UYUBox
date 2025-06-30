import time

from zilant_prime_core.utils import decoy


def test_sweep_expired_decoys_direct(tmp_path):
    # Создаём decoy-файл напрямую
    file = tmp_path / "decoy_test.zil"
    file.write_bytes(b"decoy-data")
    # Добавляем истёкший decoy вручную
    decoy._DECOY_EXPIRY[file] = time.time() - 1  # Время в прошлом
    # sweep_expired_decoys должен удалить файл и покрыть весь блок
    removed = decoy.sweep_expired_decoys(tmp_path)
    assert removed == 1
    assert not file.exists()
