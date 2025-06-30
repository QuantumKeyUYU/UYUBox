from crypto_utils import onion_decrypt, onion_encrypt


def test_onion_encrypt_decrypt():
    keys = [b"a" * 32, b"b" * 32]
    data = b"payload"
    enc = onion_encrypt(data, keys)
    assert onion_decrypt(enc, keys) == data
