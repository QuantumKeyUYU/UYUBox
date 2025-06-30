"""IPFS storage backend (not yet implemented)."""

from __future__ import annotations


def store(container: bytes) -> str:
    raise NotImplementedError


def retrieve(uri: str) -> bytes:
    raise NotImplementedError
