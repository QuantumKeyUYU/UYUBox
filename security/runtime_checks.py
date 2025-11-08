"""Runtime environment attestation helpers."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Callable, Iterable, List, Literal


Severity = Literal["warning", "critical"]


@dataclass
class SecurityIssue:
    """Represents a detected security concern in the runtime environment."""

    severity: Severity
    message: str


def _detect_root_paths() -> List[SecurityIssue]:
    suspicious_paths = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
    ]
    found = [path for path in suspicious_paths if os.path.exists(path)]
    if not found:
        return []
    return [
        SecurityIssue(
            severity="critical",
            message=f"Обнаружены следы root-доступа: {', '.join(found)}",
        )
    ]


def _detect_debuggers() -> List[SecurityIssue]:
    if sys.gettrace():
        return [
            SecurityIssue(
                severity="warning",
                message="Приложение запущено под отладчиком. Отключите debug-процессы.",
            )
        ]
    return []


def _detect_ld_preload() -> List[SecurityIssue]:
    preload = os.environ.get("LD_PRELOAD")
    if preload:
        return [
            SecurityIssue(
                severity="warning",
                message="Установлена переменная LD_PRELOAD — возможно внедрение библиотек.",
            )
        ]
    return []


def _detect_test_keys() -> List[SecurityIssue]:
    build_prop = "/system/build.prop"
    try:
        with open(build_prop, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if line.startswith("ro.build.tags=") and "test-keys" in line:
                    return [
                        SecurityIssue(
                            severity="warning",
                            message="Сборка Android подписана test-keys. Используйте доверенное устройство.",
                        )
                    ]
    except OSError:
        pass
    return []


def _detect_frida() -> List[SecurityIssue]:
    for key in ("FRIDA_VERSION", "FRIDA_DEVICE", "LIBFRIDA"):
        if key in os.environ:
            return [
                SecurityIssue(
                    severity="critical",
                    message="Обнаружены признаки инструментации (Frida).",
                )
            ]
    return []


def run_environment_checks() -> List[SecurityIssue]:
    """Run a suite of best-effort environment integrity checks."""

    detectors: Iterable[Callable[[], List[SecurityIssue]]] = (
        _detect_root_paths,
        _detect_debuggers,
        _detect_ld_preload,
        _detect_test_keys,
        _detect_frida,
    )
    issues: List[SecurityIssue] = []
    for detector in detectors:
        try:
            issues.extend(detector())
        except Exception:
            # Detection failures should not crash the app; skip silently.
            continue
    return issues


__all__ = ["SecurityIssue", "run_environment_checks"]
