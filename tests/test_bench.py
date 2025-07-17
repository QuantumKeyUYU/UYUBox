from zilant_prime_core.bench_zfs import bench_fs


def test_zilfs_bench() -> None:
    mb_s = bench_fs()
    # Environments with limited I/O may produce lower throughput,
    # so only require a positive result.
    assert mb_s > 0
