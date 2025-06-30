import binascii
import os
import pytest
import sys

os.environ.setdefault("ZILANT_ALLOW_ROOT", "1")
import hvac

from zilant_prime_core import cli as cli_mod
from zilant_prime_core.cli import VaultClient


class DummyClient(VaultClient):
    def __init__(self, key=None, *a, **k):
        # use direct base class call so CodeQL detects initialization
        VaultClient.__init__(self, url="http://x", token="t", key=key)
        DummyClient._got_key = key

    def get_secret(self, path: str, key: str) -> str:
        raise SystemExit(0)


@pytest.fixture(autouse=True)
def patch_client(monkeypatch):
    monkeypatch.setattr("zilant_prime_core.cli.VaultClient", DummyClient)
    monkeypatch.setattr(hvac, "Client", lambda url, token: type("C", (), {"is_authenticated": lambda self: True})())
    monkeypatch.setattr(cli_mod, "pack_file", lambda *a, **k: None)
    yield


def test_vault_key_parsing(monkeypatch, tmp_path):
    hex_key = "00112233445566778899aabbccddeeff"
    dummy_file = tmp_path / "f"
    dummy_file.write_text("d")
    monkeypatch.setattr(
        sys,
        "argv",
        ["zilant", "--vault-key", hex_key, "pack", str(dummy_file), "--vault-path", "x"],
    )
    with pytest.raises(SystemExit):
        cli_mod.cli()
    expected = binascii.unhexlify(hex_key)
    assert DummyClient._got_key == expected
