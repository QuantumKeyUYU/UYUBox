from zilant_prime_core.bench_zfs import bench_fs


def test_zilfs_bench() -> None:
    mb_s = bench_fs()
    assert mb_s > 5
