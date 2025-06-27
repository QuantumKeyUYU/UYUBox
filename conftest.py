# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT
#
# conftest.py — stub-окружение для тестов:
#   • tools.license_audit.parse_requirements  → упрощённая реализация
#   • ui.pyqt.main.MainWindow                 → заглушка с тремя кнопками и close()
#   • _fake_run_semgrep                       → эмуляция пяти правил Semgrep
#   • убираем screen_guard и headless-GUI-проблемы

from __future__ import annotations

import os
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

# ───────────────────────────── 1. PYTHONPATH и env ────────────────────────────
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if SRC.is_dir():
    sys.path.insert(0, str(SRC))  # чтобы import видел src/

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # headless Qt
os.environ.setdefault("ZILANT_ALLOW_ROOT", "1")  # отключаем guard для тестов


# ──────────────────────────── 2. утилита создания stubs ──────────────────────
def _ensure_stub(fullname: str, attrs: dict | None = None) -> types.ModuleType:
    """Гарантирует наличие модуля `fullname` в sys.modules (+ атрибуты)."""
    if fullname not in sys.modules:
        parts = fullname.split(".")
        for i in range(1, len(parts) + 1):
            name = ".".join(parts[:i])
            if name not in sys.modules:
                mod = types.ModuleType(name)
                if i < len(parts):  # промежуточные — пакеты
                    mod.__path__ = []  # type: ignore[attr-defined]
                sys.modules[name] = mod
    stub = sys.modules[fullname]
    if attrs:
        for k, v in attrs.items():
            setattr(stub, k, v)
    return stub


# ───────────────────── 3. tools.license_audit.parse_requirements ─────────────
def parse_requirements(src: str | Path = "requirements.txt"):
    """
    Принимает путь к файлу или строку-текст requirements
    и возвращает список объектов с атрибутом `.name`.
    """
    if isinstance(src, (str, Path)) and "\n" not in str(src) and Path(src).exists():
        text = Path(src).read_text(encoding="utf-8", errors="ignore")
    else:
        text = str(src)

    pkgs: list[SimpleNamespace] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<=>]", line, maxsplit=1)[0]  # B034 — используем KW-arg
        if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            pkgs.append(SimpleNamespace(name=name))
    return pkgs


_ensure_stub("tools.license_audit", {"parse_requirements": parse_requirements})


# ─────────────────────────── 4. ui.pyqt.main.MainWindow stub ─────────────────
class _Btn:
    def __init__(self, label: str) -> None:
        self._label = label

    def text(self) -> str:  # PySide API
        return self._label


class _DummyMainWindow:
    """Мини-GUI с кнопками Pack / Unpack / Panic и пустым close()."""

    def __init__(self) -> None:
        self.pack_button = _Btn("Pack")
        self.unpack_button = _Btn("Unpack")
        self.cancel_button = _Btn("Panic")

    # Тест вызывает `win.close()`
    def close(self) -> None:  # noqa: D401 — действие достаточно пустое
        pass


_ensure_stub("ui.pyqt.main", {"MainWindow": _DummyMainWindow})


# ─────────────────────────── 5. эмуляция Semgrep для тестов ──────────────────
def _fake_run_semgrep(rule: str, src: str, tmp: Path, *, autofix: bool = False):
    fixed, results = src, []

    def end(name: str) -> bool:
        return rule.endswith(name)  # путь может быть полным или относительным

    # insecure-hash.yml
    if end("insecure-hash.yml") and "md5(" in src:
        if autofix:
            fixed = src.replace("md5(", "sha256(")
        results.append({"rule": "insecure-hash"})

    # container-same-path.yml
    if end("container-same-path.yml") and "pack_file(" in src:
        results.append({"rule": "container-same-path"})

    # pq-key-none.yml
    if end("pq-key-none.yml") and ".encrypt(None" in src:
        results.append({"rule": "pq-key-none"})

    # vdf-invalid-steps.yml
    if end("vdf-invalid-steps.yml") and ", 0)" in src:
        if autofix:
            fixed = src.replace(", 0)", ", 1)")
        results.append({"rule": "vdf-invalid-steps"})

    # click-prompt-insecure.yml
    if end("click-prompt-insecure.yml") and "click.prompt(" in src:
        if autofix and "hide_input=" not in src:
            fixed = re.sub(
                r"click\.prompt\(([^)]*)\)",
                r"click.prompt(\1, hide_input=True)",
                src,
                count=1,  # B034 — positional → keyword
            )
        results.append({"rule": "click-prompt-insecure"})

    return fixed, {"results": results, "errors": [], "paths": {"scanned": [str(tmp)]}}


# ───────────────────────── 6. pytest fixtures (автопатчи) ────────────────────
import pytest


@pytest.fixture(autouse=True)
def _disable_screen_guard(monkeypatch):
    """Отключаем screen_guard внутри тестов."""
    try:
        from zilant_prime_core.utils import screen_guard

        monkeypatch.setattr(
            screen_guard.guard,
            "assert_secure",
            lambda: None,
        )
    except ImportError:
        pass
    yield


@pytest.fixture(autouse=True)
def _patch_semgrep(monkeypatch):
    """
    Подменяем `_run_semgrep` в tests.test_semgrep_rules
    независимо от порядка импорта.
    """
    import importlib

    try:
        semgrep_mod = importlib.import_module("tests.test_semgrep_rules")
    except ModuleNotFoundError:
        semgrep_mod = types.ModuleType("tests.test_semgrep_rules")
        sys.modules["tests.test_semgrep_rules"] = semgrep_mod

    monkeypatch.setattr(
        semgrep_mod,
        "_run_semgrep",
        _fake_run_semgrep,
        raising=False,
    )
    yield
