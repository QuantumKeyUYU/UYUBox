"""Input validation utilities for secure workflows."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterable, Optional

from security.policy import policy

PASSWORD_ENTROPY_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{12,}$")


@dataclass
class ValidationIssue:
    field: str
    message: str


def validate_file_path(
    path: str,
    *,
    must_exist: bool = True,
    max_size_mb: int | None = None,
) -> list[ValidationIssue]:
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
    limit_mb = max_size_mb if max_size_mb is not None else policy.max_file_size_mb
    max_bytes = limit_mb * 1024 * 1024
    if size_bytes and size_bytes > max_bytes:
        issues.append(
            ValidationIssue(
                "file_path",
                f"Размер файла превышает ограничение {limit_mb} МБ."
            )
        )
    return issues


def validate_password(
    password: str,
    *,
    complexity_regex: Optional[re.Pattern[str]] = PASSWORD_ENTROPY_REGEX,
) -> list[ValidationIssue]:
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


def validate_output_path(
    path: str,
    *,
    source_path: str | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    normalized = os.path.expanduser(path or "").strip()
    if not normalized:
        issues.append(ValidationIssue("output_path", "Укажите путь назначения."))
        return issues

    if os.path.isdir(normalized):
        issues.append(ValidationIssue("output_path", "Укажите файл, а не каталог."))
        return issues

    directory = os.path.dirname(normalized) or os.getcwd()
    if not os.path.exists(directory):
        issues.append(ValidationIssue("output_path", "Каталог назначения не найден."))
        return issues
    if not os.path.isdir(directory):
        issues.append(ValidationIssue("output_path", "Каталог назначения не найден."))
        return issues
    if not os.access(directory, os.W_OK):
        issues.append(ValidationIssue("output_path", "Нет прав на запись в каталог назначения."))

    if source_path:
        source_normalized = os.path.abspath(os.path.expanduser(source_path.strip()))
        if os.path.abspath(normalized) == source_normalized:
            issues.append(
                ValidationIssue(
                    "output_path",
                    "Путь назначения совпадает с исходным файлом. Выберите другой путь."
                )
            )

    return issues


def collect_issues(*sources: Iterable[ValidationIssue]) -> list[ValidationIssue]:
    aggregated: list[ValidationIssue] = []
    for source in sources:
        aggregated.extend(source)
    return aggregated
