import importlib


def test_policy_env_overrides(monkeypatch):
    monkeypatch.setenv("ZILANT_SESSION_TTL", "600")
    monkeypatch.setenv("ZILANT_MAX_FILE_MB", "1024")
    monkeypatch.setenv("ZILANT_MIN_FREE_MB", "128")
    monkeypatch.setenv("ZILANT_HEADROOM_MB", "32")

    policy_module = importlib.import_module("security.policy")
    reloaded = importlib.reload(policy_module)

    try:
        policy = reloaded.policy
        assert policy.session_ttl == 600.0
        assert policy.max_file_size_mb == 1024
        assert policy.min_free_space_mb == 128
        assert policy.headroom_mb == 32
    finally:
        monkeypatch.delenv("ZILANT_SESSION_TTL", raising=False)
        monkeypatch.delenv("ZILANT_MAX_FILE_MB", raising=False)
        monkeypatch.delenv("ZILANT_MIN_FREE_MB", raising=False)
        monkeypatch.delenv("ZILANT_HEADROOM_MB", raising=False)
        importlib.reload(policy_module)
