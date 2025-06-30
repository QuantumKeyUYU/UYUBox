from shamir import split_secret, recover_secret


def test_split_secret():
    secret = 123456789
    parts = split_secret(secret, n=5, k=3)
    assert len(parts) == 5
    xs = {x for x, _ in parts}
    assert len(xs) == 5


def test_reconstruct_secret_success():
    secret = 424242
    shares = split_secret(secret, n=6, k=4)
    assert recover_secret(shares[:4]) == secret
    assert recover_secret(shares) == secret


def test_reconstruct_secret_failure():
    secret = 9999
    shares = split_secret(secret, n=5, k=4)
    partial = shares[:3]
    assert recover_secret(partial) != secret


def test_edge_cases():
    secret = 77
    one_share = split_secret(secret, n=1, k=1)
    assert recover_secret(one_share) == secret

    secret2 = 88
    all_required = split_secret(secret2, n=4, k=4)
    assert recover_secret(all_required) == secret2
