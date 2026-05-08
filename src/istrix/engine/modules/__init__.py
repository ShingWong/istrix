"""Pluggable scan modules for iStrix follow-up tasks.

Modules are auto-discovered at import time by scanning this directory for
ScanModule subclasses.  Hardcoded imports are retained as a guaranteed
baseline; any `.py` file placed in this directory whose top-level class
inherits from ScanModule will be automatically registered.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path

from istrix.engine.modules.base import ScanModule
from istrix.engine.modules.http_probe import HTTPProbeModule
from istrix.engine.modules.ssl_check import SSLCheckModule
from istrix.engine.modules.dir_bust import DirBustModule

# Built-in baseline — always registered
_MODULE_REGISTRY: dict[str, type[ScanModule]] = {
    "http_probe": HTTPProbeModule,
    "ssl_check": SSLCheckModule,
    "dir_bust": DirBustModule,
}


def _discover_modules() -> dict[str, type[ScanModule]]:
    """Auto-discover ScanModule subclasses in this package directory."""
    registry = dict(_MODULE_REGISTRY)

    modules_dir = Path(__file__).parent
    package_name = __name__

    for _, module_name, _ in pkgutil.iter_modules([str(modules_dir)]):
        if module_name in ("base", "__init__"):
            continue

        try:
            module = importlib.import_module(f".{module_name}", package=package_name)
        except Exception:
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, ScanModule) or obj is ScanModule:
                continue
            if getattr(obj, "name", None) is None:
                continue
            if obj.name not in registry:
                registry[obj.name] = obj

    return registry


MODULE_REGISTRY: dict[str, type[ScanModule]] = _discover_modules()

__all__ = ["ScanModule", "HTTPProbeModule", "SSLCheckModule", "DirBustModule",
           "MODULE_REGISTRY"]
