# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

"""Мини-«пейзаж» из (clauses, salts) с добровольной strict-валидацией."""

from __future__ import annotations

import random


def generate_landscape(size: int, *, strict: bool = False) -> tuple[list[int], list[int]]:
    if size <= 0:
        raise ValueError("size must be positive")

    clauses: list[int] = []
    salts: list[int] = []

    for _ in range(size):
        clause = random.randint(0, 1) if strict else random.randint(0, 255)
        clauses.append(clause)
        salts.append(random.randint(0, 2**31 - 1))

    return clauses, salts


def verify_landscape(obj: object, *, strict: bool = False) -> bool:
    # Проверяем структуру
    if not isinstance(obj, tuple) or len(obj) != 2 or not all(isinstance(lst, list) for lst in obj):
        raise ValueError("Landscape must be tuple(List[int], List[int])")

    clauses, salts = obj
    if len(clauses) != len(salts):
        raise ValueError("Clauses and salts must have same length")

    # Явно указываем strict=…, чтобы Ruff не ругался на zip без strict
    for clause, salt in zip(clauses, salts, strict=strict):
        if not isinstance(clause, int) or not isinstance(salt, int):
            return False
        if strict and clause not in (0, 1):
            return False

    return True
