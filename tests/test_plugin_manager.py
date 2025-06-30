# tests/test_plugin_manager.py

import json
import pytest

from src.plugin_manager import PluginManager


@pytest.fixture
def plugins_dir(tmp_path):
    # создаём папку и конфиг
    pdir = tmp_path / "plugins"
    pdir.mkdir()
    cfg = {"plugins": ["alpha", "beta"]}
    (pdir / "plugins.json").write_text(json.dumps(cfg), encoding="utf-8")
    # создаём два «плагина»
    (pdir / "alpha.py").write_text("value = 'A'", encoding="utf-8")
    (pdir / "beta.py").write_text("value = 'B'", encoding="utf-8")
    return pdir


def test_discover_returns_list(plugins_dir):
    pm = PluginManager(str(plugins_dir))
    found = pm.discover()
    assert found == ["alpha", "beta"]


def test_discover_empty_if_no_config(tmp_path):
    pdir = tmp_path / "empty"
    pdir.mkdir()
    pm = PluginManager(str(pdir))
    assert pm.discover() == []


def test_load_existing_plugin(plugins_dir):
    pm = PluginManager(str(plugins_dir))
    mod = pm.load("alpha")
    # в alpha.py мы прописали переменную value
    assert hasattr(mod, "value") and mod.value == "A"


def test_load_missing_plugin_raises(plugins_dir):
    pm = PluginManager(str(plugins_dir))
    with pytest.raises(ImportError):
        pm.load("gamma")
