# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from zilant_prime_core.self_heal import monitor


def test_handler_on_modified_wrong_path(tmp_path):
    # В src_path не совпадает путь — ветка не вызовет ничего, не должно падать
    handler = monitor._Handler(tmp_path / "a.txt")

    class DummyEvent:
        src_path = str(tmp_path / "b.txt")

    handler.on_modified(DummyEvent())
