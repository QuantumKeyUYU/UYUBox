from __future__ import annotations

"""Simple plugin manager loading modules from a directory."""

import importlib.util
import json
from pathlib import Path
from typing import Any, List


class PluginManager:
    """Discover and load plugins located in ``plugin_dir``."""

    def __init__(self, plugin_dir: str) -> None:
        self.plugin_dir = Path(plugin_dir)
        self.config = self.plugin_dir / "plugins.json"

    def discover(self) -> List[str]:
        if not self.config.exists():
            return []
        data = json.loads(self.config.read_text())
        plugins = data.get("plugins", [])
        return list(plugins)

    def load(self, name: str) -> Any:
        """Load plugin module by ``name``."""
        path = self.plugin_dir / f"{name}.py"
        if not path.exists():
            raise ImportError(name)
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[arg-type]
        return module
