from zilant_prime_core.crypto.fractal_kdf import fractal_kdf


def test_fractal_unique_and_deterministic(tmp_path):
    seed1 = b"a" * 32
    seed2 = b"b" * 32
    assert fractal_kdf(seed1) == fractal_kdf(seed1)
    assert fractal_kdf(seed1) != fractal_kdf(seed2)
