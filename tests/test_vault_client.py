# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
import hvac
import os
import pytest

from zilant_prime_core.utils.vault_client import VaultClient

# ─── Заглушки hvac.Client ─────────────────────────────────────────────────────────


class DummyKVv2:
    def __init__(self, data: dict[str, str], fail: bool = False) -> None:
        self._data = data
        self._fail = fail

    def read_secret_version(self, path: str, mount_point: str) -> dict[str, dict[str, dict[str, str]]]:
        if self._fail:
            raise Exception("Simulated v2 error")
        return {"data": {"data": self._data}}


class DummyClientKV2:
    def __init__(self, data: dict[str, str], fail: bool = False) -> None:
        self._data = data
        self.secrets = type("S", (), {"kv": type("KV", (), {"v2": DummyKVv2(self._data, fail=fail)})})
        self._auth = True

    def is_authenticated(self) -> bool:
        return self._auth

    def read(self, path: str) -> dict[str, dict[str, str]] | None:
        return None


class DummyClientKV1:
    def __init__(self, data: dict[str, str], fail: bool = False, missing_data: bool = False) -> None:
        self._data = data
        self._auth = True
        self._fail = fail
        self._missing_data = missing_data
        self.secrets = type("S", (), {"kv": None})

    def is_authenticated(self) -> bool:
        return self._auth

    def read(self, path: str) -> dict[str, dict[str, str]] | None:
        if self._fail:
            raise Exception("Simulated v1 error")
        if self._missing_data:
            return {}  # Нет "data" ключа
        return {"data": self._data}


def test_get_secret_kv2_success(monkeypatch) -> None:
    os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
    os.environ["VAULT_TOKEN"] = "token123"
    monkeypatch.setattr(hvac, "Client", lambda url, token: DummyClientKV2({"x": "y"}))
    client = VaultClient()
    assert client.get_secret("secret/data/app", "x") == "y"


def test_get_secret_kv2_key_missing(monkeypatch) -> None:
    os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
    os.environ["VAULT_TOKEN"] = "token123"
    monkeypatch.setattr(hvac, "Client", lambda url, token: DummyClientKV2({"a": "b"}))
    client = VaultClient()
    with pytest.raises(KeyError):
        client.get_secret("secret/data/app", "x")


def test_get_secret_fallback_to_kv1(monkeypatch) -> None:
    os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
    os.environ["VAULT_TOKEN"] = "token123"
    # v2 падает, v1 возвращает значение
    monkeypatch.setattr(hvac, "Client", lambda url, token: DummyClientKV1({"key1": "val1"}))
    client = VaultClient()
    assert client.get_secret("secret/app", "key1") == "val1"


def test_fallback_key_missing(monkeypatch) -> None:
    os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
    os.environ["VAULT_TOKEN"] = "token123"
    monkeypatch.setattr(hvac, "Client", lambda url, token: DummyClientKV1({"other": "val"}))
    client = VaultClient()
    with pytest.raises(KeyError):
        client.get_secret("secret/app", "missing")


def test_missing_env_vars() -> None:
    os.environ.pop("VAULT_ADDR", None)
    os.environ.pop("VAULT_TOKEN", None)
    with pytest.raises(ValueError):
        VaultClient()


def test_kv1_path_not_found(monkeypatch) -> None:
    """
    v2 падает, v1 возвращает None или dict без "data": KeyError должен быть пойман (coverage!)
    """
    os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
    os.environ["VAULT_TOKEN"] = "token123"

    class BrokenClient(DummyClientKV1):
        def read(self, path: str):
            return {}  # Нет "data" ключа

    # v2 падает, v1 не находит путь
    monkeypatch.setattr(hvac, "Client", lambda url, token: BrokenClient({}))
    client = VaultClient()
    with pytest.raises(KeyError):
        client.get_secret("secret/app", "key1")


def test_kv1_general_error(monkeypatch) -> None:
    """
    v2 падает, v1 падает с Exception — KeyError должен быть проброшен (coverage!)
    """
    os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
    os.environ["VAULT_TOKEN"] = "token123"

    class ErrorClient(DummyClientKV1):
        def read(self, path: str):
            raise Exception("Simulated v1 failure")

    # v2 падает, v1 бросает Exception
    monkeypatch.setattr(hvac, "Client", lambda url, token: ErrorClient({}, fail=True))
    client = VaultClient()
    with pytest.raises(KeyError):
        client.get_secret("secret/app", "key1")


def test_vault_client_auth_failed(monkeypatch):
    """
    VaultClient должен выбросить ConnectionError, если client.is_authenticated() == False.
    """
    os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"
    os.environ["VAULT_TOKEN"] = "bad-token"

    class BadAuthClient:
        def __init__(self, *a, **kw):
            self.secrets = type("S", (), {"kv": None})

        def is_authenticated(self):
            return False

    monkeypatch.setattr(hvac, "Client", BadAuthClient)
    with pytest.raises(ConnectionError):
        VaultClient()
