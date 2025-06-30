from zilant_prime_core.crypto_core import derive_key_double


def test_double_kdf_length_and_determinism():
    pwd = b"pw"
    salt = b"salt123456789012"
    k1 = derive_key_double(pwd, salt)
    k2 = derive_key_double(pwd, salt)
    assert k1 == k2 and len(k1) == 32
    k3 = derive_key_double(pwd + b"x", salt)
    assert k3 != k1
