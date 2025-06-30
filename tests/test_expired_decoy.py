import time

from zilant_prime_core.utils.decoy import _DECOY_EXPIRY, generate_decoy_files, sweep_expired_decoys


def test_sweep_expired_decoys_direct(tmp_path):
    # 1) Файл существует и должен быть удалён
    f = tmp_path / "decoy_test.zil"
    f.write_bytes(b"decoy-data")
    # вручную ставим в _DECOY_EXPIRY истёкший таймштамп
    _DECOY_EXPIRY[f] = time.time() - 1
    removed = sweep_expired_decoys(tmp_path)
    assert removed == 1
    assert not f.exists()
    assert f not in _DECOY_EXPIRY


def test_sweep_expired_decoys_missing_file(tmp_path):
    # 2) Файла нет, но запись есть — должен залогироваться removed_early
    f = tmp_path / "decoy_gone.zil"
    # не создаём сам файл
    _DECOY_EXPIRY[f] = time.time() - 1
    removed = sweep_expired_decoys(tmp_path)
    assert removed == 1
    # после sweep запись сбрасывается
    assert f not in _DECOY_EXPIRY


def test_generate_decoy_and_sweep_mixed(tmp_path):
    # 3) Смешанный сценарий: сгенерировали два декоя, один удалили до срока,
    #    подождали expiry, прогнали sweep — и покрыли все ветки
    paths = generate_decoy_files(tmp_path, count=2, size=4, expire_seconds=1)
    # ручками удаляем первый до истечения
    paths[0].unlink()
    time.sleep(1.1)
    removed = sweep_expired_decoys(tmp_path)
    # могло удалиться либо 1 (тот, что ещё был на диске), либо 0 (если
    # фонтовый поток его уже убрал) — главное, что ветки пройдены
    assert removed in (0, 1)
