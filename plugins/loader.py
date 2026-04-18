"""
Plugin Loader
Automatically discovers and loads all plugins from the plugins/ directory.
Validates the plugin API contract before loading.
"""
import importlib
import inspect
from pathlib import Path
from typing import List, Type, Dict
from loguru import logger

from plugins.base import WAPTPlugin


class PluginLoader:
    """
    Scans the plugins/ directory, imports each module,
    finds WAPTPlugin subclasses, validates them, and returns
    a registry of available plugins.
    """

    PLUGIN_DIR = Path("plugins")

    def __init__(self):
        self._registry: Dict[str, Type[WAPTPlugin]] = {}

    def discover(self) -> Dict[str, Type[WAPTPlugin]]:
        """
        Walk the plugins/ directory and import all .py files.
        Returns a dict of {plugin_name: PluginClass}.
        """
        self._registry = {}
        plugin_files = [
            f for f in self.PLUGIN_DIR.glob("*.py")
            if f.name not in ("__init__.py", "base.py", "loader.py")
            and not f.name.startswith("_")
        ]

        logger.info(f"[Plugins] Discovering plugins in {self.PLUGIN_DIR}/")

        for plugin_file in plugin_files:
            self._load_file(plugin_file)

        logger.info(
            f"[Plugins] Loaded {len(self._registry)} plugin(s): "
            f"{list(self._registry.keys())}"
        )
        return self._registry

    def _load_file(self, plugin_file: Path) -> None:
        """Import a plugin file and register valid WAPTPlugin subclasses."""
        module_name = f"plugins.{plugin_file.stem}"
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            logger.warning(f"[Plugins] Could not import {plugin_file.name}: {e}")
            return
        except Exception as e:
            logger.error(f"[Plugins] Error loading {plugin_file.name}: {e}")
            return

        # Find all WAPTPlugin subclasses in the module
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if (
                inspect.isclass(obj)
                and issubclass(obj, WAPTPlugin)
                and obj is not WAPTPlugin
            ):
                valid, reason = self._validate(obj)
                if valid:
                    self._registry[obj.name] = obj
                    logger.success(
                        f"[Plugins] Loaded: '{obj.name}' "
                        f"v{obj.version} by {obj.author}"
                    )
                else:
                    logger.warning(
                        f"[Plugins] Skipped {attr_name} in {plugin_file.name}: {reason}"
                    )

    def _validate(self, plugin_cls: Type[WAPTPlugin]) -> tuple[bool, str]:
        """
        Validate plugin meets the minimum contract:
          - Has a unique non-default name
          - Has a run() method
          - Has required metadata
        """
        if plugin_cls.name == "unnamed_plugin":
            return False, "Plugin must set a unique 'name' class attribute"

        if plugin_cls.name in self._registry:
            return False, f"Duplicate plugin name: '{plugin_cls.name}'"

        if not inspect.iscoroutinefunction(getattr(plugin_cls, "run", None)):
            return False, "Plugin must implement an async run() method"

        if not plugin_cls.description:
            return False, "Plugin must set a 'description' class attribute"

        return True, ""

    def get_by_category(self, category: str) -> List[Type[WAPTPlugin]]:
        """Return all plugins matching a category."""
        return [
            cls for cls in self._registry.values()
            if cls.category == category
        ]

    def get_by_name(self, name: str) -> Type[WAPTPlugin]:
        """Return a plugin class by name."""
        if name not in self._registry:
            raise KeyError(f"Plugin '{name}' not found. "
                           f"Available: {list(self._registry.keys())}")
        return self._registry[name]

    @property
    def all_plugins(self) -> List[Type[WAPTPlugin]]:
        return list(self._registry.values())


# Global loader instance
plugin_loader = PluginLoader()
