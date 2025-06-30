# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import logging
import os
from typing import Optional, Union

from zilant_prime_core.utils.secure_logging import SecureLogger, get_secure_logger

__all__ = ["get_logger", "get_file_logger"]


def get_logger(
    name: str, *, secure: Optional[bool] = None, log_path: Optional[str] = None
) -> Union[logging.Logger, SecureLogger]:
    """
    Возвращает либо обычный logging.Logger, либо SecureLogger, в зависимости
    от флага secure или переменной среды ZILANT_SECURE_LOG=1.

    - name: имя логгера (используется только для обычного Logger).
    - secure: если True, возвращаем SecureLogger. Если False, обычный Logger.
      Если None, проверяем ZILANT_SECURE_LOG в окружении.
    - log_path: путь до файла лога (для SecureLogger). Если None и нужен SecureLogger,
      используется “secure.log” в текущей директории.
    """
    want_secure = False
    if secure is True:
        want_secure = True
    elif secure is False:
        want_secure = False
    else:
        # secure is None → смотрим окружение
        want_secure = os.getenv("ZILANT_SECURE_LOG", "") == "1"

    if want_secure:
        # Гарантируем, что log_path будет непустой строкой
        path = log_path or "secure.log"
        return get_secure_logger(log_path=path)

    # Обычный Logger
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def get_file_logger(
    name: str, file_path: str, *, secure: Optional[bool] = None, log_path: Optional[str] = None
) -> Union[logging.Logger, SecureLogger]:
    """
    Возвращает файловый логгер:
    - Если secure=True или ZILANT_SECURE_LOG=1, возвращаем SecureLogger,
      настроенный на запись в file_path. В этом случае параметр file_path
      игнорируется, вместо него используется log_path (или “secure.log”).
    - Иначе возвращаем обычный logging.Logger с FileHandler → file_path.
    """
    want_secure = False
    if secure is True:
        want_secure = True
    elif secure is False:
        want_secure = False
    else:
        want_secure = os.getenv("ZILANT_SECURE_LOG", "") == "1"

    if want_secure:
        # Для SecureLogger логический путь – это log_path
        path = log_path or "secure.log"
        return get_secure_logger(log_path=path)

    # Обычный файловый логгер
    logger = logging.getLogger(name)
    if not logger.handlers:
        fh = logging.FileHandler(file_path)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        logger.addHandler(fh)
        logger.setLevel(logging.INFO)
    return logger
