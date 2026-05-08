"""iStrix plugin registry — auto-discovery and centralized management.

Discovers and manages three plugin types:
  - tools/      → BaseTool subclasses
  - engine/modules/ → ScanModule subclasses (existing)
  - knowledge/  → BaseKnowledge subclasses

Plugins can be enabled/disabled at runtime through the registry.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path

from istrix.plugins.base import BaseTool, BaseKnowledge
from istrix.engine.modules import MODULE_REGISTRY
from istrix.engine.modules.base import ScanModule


class PluginRegistry:
    """Centralised registry for all iStrix plugins."""

    def __init__(self):
        self.tools: dict[str, BaseTool] = {}
        self.knowledge: dict[str, BaseKnowledge] = {}
        self.skills: dict[str, type[ScanModule]] = dict(MODULE_REGISTRY)
        self._discovered = False

    def discover(self) -> None:
        """Auto-discover all plugins from the filesystem."""
        if self._discovered:
            return
        self._discover_from("istrix.plugins.tools", BaseTool, self.tools)
        self._discover_from("istrix.plugins.knowledge", BaseKnowledge, self.knowledge)
        # Skills are already loaded via MODULE_REGISTRY auto-discovery
        self._discovered = True

    @staticmethod
    def _discover_from(package_name: str, base_class: type, registry: dict) -> None:
        """Import all subclasses of base_class from a package."""
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return

        pkg_path = Path(package.__file__).parent if package.__file__ else None
        if not pkg_path:
            return

        for _, module_name, _ in pkgutil.iter_modules([str(pkg_path)]):
            if module_name.startswith("_"):
                continue
            try:
                module = importlib.import_module(f".{module_name}", package=package_name)
            except Exception:
                continue

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if not issubclass(obj, base_class) or obj is base_class:
                    continue
                name = getattr(obj, "name", None)
                if name and name not in registry:
                    registry[name] = obj()

    def list_tools(self) -> list[dict]:
        return [{"name": n, "desc": t.description, "available": t.is_available()}
                for n, t in self.tools.items()]

    def list_knowledge(self) -> list[dict]:
        return [{"name": n, "desc": k.description} for n, k in self.knowledge.items()]

    def list_skills(self) -> list[dict]:
        return [{"name": n, "desc": cls.description, "consumed": cls.consumed_types,
                 "produced": cls.produced_types}
                for n, cls in self.skills.items()]

    def get_tool(self, name: str) -> BaseTool | None:
        return self.tools.get(name)

    def get_knowledge(self, name: str) -> BaseKnowledge | None:
        return self.knowledge.get(name)

    def get_skill(self, name: str) -> type[ScanModule] | None:
        return self.skills.get(name)


# Singleton
plugin_registry = PluginRegistry()
