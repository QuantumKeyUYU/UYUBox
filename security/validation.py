"""Input validation utilities for secure workflows."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterable, Optional

PASSWORD_ENTROPY_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{12,}$")


@dataclass
class ValidationIssue:
    field: str
    message: str


def validate_file_path(path: str, *, must_exist: bool = True, max_size_mb: int = 512) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    normalized = os.path.expanduser(path or "").strip()
    if not normalized:
        issues.append(ValidationIssue("file_path", "Укажите путь к файлу."))
        return issues
    if must_exist and not os.path.exists(normalized):
        issues.append(ValidationIssue("file_path", "Файл не найден."))
        return issues
    if must_exist and not os.path.isfile(normalized):
        issues.append(ValidationIssue("file_path", "Укажите корректный файл, а не каталог."))
    try:
        size_bytes = os.path.getsize(normalized)
    except OSError:
        size_bytes = 0
    if size_bytes and size_bytes > max_size_mb * 1024 * 1024:
        issues.append(
            ValidationIssue(
                "file_path",
                f"Размер файла превышает ограничение {max_size_mb} МБ."
            )
        )
    return issues


def validate_password(password: str, *, complexity_regex: Optional[re.Pattern[str]] = PASSWORD_ENTROPY_REGEX) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not password:
        issues.append(ValidationIssue("password", "Введите пароль."))
        return issues
    if complexity_regex and not complexity_regex.match(password):
        issues.append(
            ValidationIssue(
                "password",
                "Пароль должен содержать 12+ символов, числа, заглавные/строчные буквы и спецсимволы."
            )
        )
    return issues


def collect_issues(*sources: Iterable[ValidationIssue]) -> list[ValidationIssue]:
    aggregated: list[ValidationIssue] = []
    for source in sources:
        aggregated.extend(source)
    return aggregated
