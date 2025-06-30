"""Negative-path тесты для PluginManager, добиваем ветки исключений."""

import pytest
from pathlib import Path

from src.plugin_manager import PluginManager


def test_load_absent_plugin_raises(tmp_path: Path) -> None:
    """Попытка загрузить несуществующий плагин должна бросать ImportError."""
    pm = PluginManager(str(tmp_path))
    with pytest.raises(ImportError):
        pm.load("ghost_plugin")
