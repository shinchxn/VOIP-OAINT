"""
VoIP OSINT APEX — Plugin Registry
Manages discovery, loading, and lifecycle of investigative modules.
"""

import importlib
import inspect
import logging
import pkgutil
from typing import Dict, List, Type, Optional

from core.base_plugin import BasePlugin

log = logging.getLogger("plugin_registry")

class PluginRegistry:
    """
    Central registry for managing investigative plugins.
    Supports dynamic discovery from the 'modules' directory.
    """

    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}

    def discover(self, package_path: str = "modules"):
        """
        Scan a package for classes inheriting from BasePlugin and register them.
        """
        try:
            package = importlib.import_module(package_path)
        except ImportError as e:
            log.error(f"Failed to import plugin package {package_path}: {e}")
            return

        for loader, module_name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            try:
                module = importlib.import_module(module_name)
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                        plugin_instance = obj()
                        meta = plugin_instance.metadata
                        self.register(plugin_instance)
            except Exception as e:
                log.warning(f"Failed to load module {module_name}: {e}")

    def register(self, plugin: BasePlugin):
        """Register a plugin instance."""
        name = plugin.metadata.name
        if name in self.plugins:
            log.warning(f"Plugin '{name}' is already registered. Overwriting.")
        self.plugins[name] = plugin
        log.info(f"Registered plugin: {name} v{plugin.metadata.version} [{plugin.metadata.category}]")

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Retrieve a plugin by name."""
        return self.plugins.get(name)

    def list_plugins(self, category: Optional[str] = None) -> List[BasePlugin]:
        """List all registered plugins, optionally filtered by category."""
        if category:
            return [p for p in self.plugins.values() if p.metadata.category == category]
        return list(self.plugins.values())

# Global registry instance
registry = PluginRegistry()
