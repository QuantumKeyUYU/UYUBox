# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

__all__ = [
    "GNewError",
    "G_new",
]

# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# src/zilant_prime_core/crypto/g_new.py

import math


class GNewError(Exception):
    """Ошибка в модуле G_new."""


def G_new(x: float) -> float:
    """
    Синус-резонансная геометрия:
      - низкочастотный резонанс: sin(x) * cos(x/2)
      - высокочастотный резонанс: 0.5 * sin(3*x)
    Возвращает «энергетический угол» для дальнейшего принятия решения
    (например, переключения между классикой и G_new-модулем).

    Аргументы:
      x: float — входной параметр (угол, плотность, любой числовой признак).

    Возвращает:
      float — значение «энергетического угла».

    Генерирует GNewError при неверном типе входного параметра.
    """
    if not isinstance(x, (int, float)):
        raise GNewError(f"Input must be int or float, got {type(x).__name__}")
    # Сводим в диапазон [0, 2π) для предсказуемости резонансов
    theta = float(x) % (2 * math.pi)
    # Комбинация низко- и высокочастотной синусоид
    low_freq = math.sin(theta) * math.cos(theta / 2)
    high_freq = 0.5 * math.sin(3 * theta)
    return low_freq + high_freq
