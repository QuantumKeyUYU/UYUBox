"""Unit-тестируем внутренние helpers из zilfs.py (Windows-ветка)."""

from __future__ import annotations

import types
from pathlib import Path

from zilant_prime_core import zilfs


def test_mark_sparse_noop(monkeypatch, tmp_path: Path) -> None:
    """Проверяем, что _mark_sparse не падает, даже если kernel32 = заглушка."""
    fake = types.SimpleNamespace(DeviceIoControl=lambda *_a, **_kw: None)
    monkeypatch.setattr(zilfs, "kernel32", fake, raising=False)
    dummy = tmp_path / "d.bin"
    dummy.touch()
    zilfs._mark_sparse(dummy)  # должно выполниться без исключения


def test_sparse_copyfile2_fallback(monkeypatch, tmp_path: Path) -> None:
    """
    Эмулируем WinError 112 (нет места) в CopyFile2 и убеждаемся, что
    fallback-логика создаёт правильный «разрежённый» файл-приёмник.
    """

    class StubWinAPI:  # pylint: disable=too-few-public-methods
        def CopyFile2(self, *_a, **_kw):  # noqa: N802  pylint: disable=invalid-name
            err = OSError()
            err.winerror = 112  # ENOSPC
            raise err

    monkeypatch.setattr(zilfs, "_winapi", StubWinAPI(), raising=False)

    src, dst = (tmp_path / "a.bin"), (tmp_path / "b.bin")
    src.write_bytes(b"123")
    zilfs._sparse_copyfile2(str(src), str(dst), 0)  # type: ignore[attr-defined]
    assert dst.exists() and dst.read_bytes() == b"\x00" * 3


def test_zero_file_read_cycle() -> None:
    """_ZeroFile должен корректно отдавать нужное кол-во нулей и EOF."""
    zf = zilfs._ZeroFile(3)  # type: ignore[attr-defined]
    assert zf.read(2) == b"\0\0"
    assert zf.read(10) == b"\0"  # остаток
    assert zf.read(1) == b""  # EOF
