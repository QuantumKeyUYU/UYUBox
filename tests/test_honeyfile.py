# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import pytest

from zilant_prime_core.utils.honeyfile import HoneyfileError, check_tmp_for_honeyfiles, create_honeyfile, is_honeyfile


def test_detect_honeyfile(tmp_path):
    f = tmp_path / "secret.doc"
    # Создаём honeyfile с маркером!
    create_honeyfile(str(f))
    assert is_honeyfile(str(f))
    # Проверка на выброс исключения:
    with pytest.raises(HoneyfileError):
        check_tmp_for_honeyfiles(str(tmp_path))
