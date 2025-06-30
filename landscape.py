# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

"""
Generators and validators for SAT formulas and landscapes.

- generate_sat: random 3-CNF formula
- generate_landscape: (clauses, salts) generator
- verify_landscape: validator for generated landscapes
"""

import random


def generate_sat(variables: int, density: float) -> list[list[int]]:
    if not isinstance(variables, int) or variables <= 0:
        raise ValueError("Number of variables must be a positive integer.")
    if not isinstance(density, (int, float)) or density < 0:
        raise ValueError("Density must be non-negative.")

    num_clauses = int(variables * density)
    formula: list[list[int]] = []
    for _ in range(num_clauses):
        picks = random.sample(range(1, variables + 1), k=min(3, variables))
        clause: list[int] = []
        for v in picks:
            lit = v if random.choice([True, False]) else -v
            clause.append(lit)
        formula.append(clause)
    return formula


def generate_landscape(size: int, *, strict: bool = False) -> tuple[list[int], list[int]]:
    if not isinstance(size, int) or size <= 0:
        raise ValueError("size must be positive integer")

    clauses: list[int] = []
    salts: list[int] = []
    for _ in range(size):
        clause = random.randint(0, 1) if strict else random.randint(0, 255)
        clauses.append(clause)
        salts.append(random.randint(0, 2**31 - 1))
    return clauses, salts


def verify_landscape(obj: object, *, strict: bool = False) -> bool:
    if not isinstance(obj, tuple) or len(obj) != 2:
        raise ValueError("Landscape must be tuple(List[int], List[int])")
    clauses, salts = obj
    if not isinstance(clauses, list) or not isinstance(salts, list):
        raise ValueError("Landscape must be tuple(List[int], List[int])")
    if len(clauses) != len(salts):
        raise ValueError("Clauses and salts must have same length")

    # enforce equal lengths strictly
    for clause, salt in zip(clauses, salts, strict=True):
        if not isinstance(clause, int) or not isinstance(salt, int):
            return False
        if strict and clause not in (0, 1):
            return False
    return True
