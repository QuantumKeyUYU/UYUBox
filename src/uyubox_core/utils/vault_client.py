# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from __future__ import annotations

import hvac
import os
from typing import Any

__all__ = ["VaultClient"]


class VaultClient:
    def __init__(self, url: str | None = None, token: str | None = None, key: bytes | None = None) -> None:
        self._url: str = (url or os.getenv("VAULT_ADDR") or "").strip()
        self._token: str = (token or os.getenv("VAULT_TOKEN") or "").strip()
        self.key = key
        if not self._url or not self._token:
            raise ValueError("VAULT_ADDR / VAULT_TOKEN не заданы")

        self._client = hvac.Client(url=self._url, token=self._token)
        if not self._client.is_authenticated():
            raise ConnectionError("Аутентификация в Vault не удалась")

    def get_secret(self, path: str, key: str) -> str:
        mount, _, relative = path.partition("/")

        # KV v2
        try:
            resp: Any = self._client.secrets.kv.v2.read_secret_version(
                mount_point=mount,
                path=relative,
            )
            # Явно убеждаемся, что это dict
            if isinstance(resp, dict) and "data" in resp and "data" in resp["data"]:
                data = resp["data"]["data"]
                return self._extract(data, key, path)
        except Exception:
            ...

        # KV v1
        try:
            wrapper: Any = self._client.read(path)
            if isinstance(wrapper, dict) and "data" in wrapper:
                return self._extract(wrapper["data"], key, path)
            raise KeyError
        except Exception:
            raise KeyError(f"Ключ '{key}' или путь '{path}' не найдены") from None

    @staticmethod
    def _extract(data: Any, key: str, path: str) -> str:
        if not isinstance(data, dict) or key not in data:
            raise KeyError(f"Ключ '{key}' не найден в '{path}'")
        return str(data[key])
