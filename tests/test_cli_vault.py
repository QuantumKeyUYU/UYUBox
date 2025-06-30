import binascii
import pytest

import zilant_prime_core.cli as cli_mod


def test_cli_vault_key_parsing(monkeypatch, tmp_path):
    called = {}

    class DummyVC:
        def __init__(self, *, key=None):
            called["key"] = key

        def get_secret(self, path: str, key: str) -> str:
            raise SystemExit(0)

    monkeypatch.setattr(cli_mod, "VaultClient", DummyVC)
    monkeypatch.setattr(cli_mod, "pack_file", lambda *a, **k: None)

    src = tmp_path / "f"
    src.write_text("data")
    monkeypatch.setattr(
        "sys.argv",
        ["zilant", "--vault-key", "a1b2c3", "pack", str(src), "--vault-path", "x"],
    )
    with pytest.raises(SystemExit):
        cli_mod.cli()
    assert called["key"] == binascii.unhexlify("a1b2c3")
