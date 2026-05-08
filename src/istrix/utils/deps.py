"""External tool dependency checking."""

import shutil
from dataclasses import dataclass


@dataclass
class ToolStatus:
    """Status of an external tool dependency."""

    name: str
    path: str | None = None
    available: bool = False
    required: bool = True
    version: str | None = None
    message: str = ""


REQUIRED_TOOLS: dict[str, dict] = {
    "nmap": {"required": True, "check_flag": "--version", "min_version": None},
    "rustscan": {"required": False, "check_flag": "--version", "min_version": None},
    "whatweb": {"required": False, "check_flag": "--version", "min_version": None},
    "nikto": {"required": False, "check_flag": "-Version", "min_version": None},
}

OPTIONAL_MODULES: list[str] = ["http_probe", "ssl_check", "dir_bust"]


def check_tools() -> list[ToolStatus]:
    """Check availability of all required and optional external tools.

    Returns a list of ToolStatus objects. Required tools with available=False
    indicate the tool cannot function. Optional tools with available=False
    mean some features are degraded.
    """
    results: list[ToolStatus] = []

    for name, cfg in REQUIRED_TOOLS.items():
        path = shutil.which(name)
        status = ToolStatus(
            name=name,
            path=path,
            available=path is not None,
            required=cfg["required"],
        )
        if path is None:
            if cfg["required"]:
                status.message = f"{name} is REQUIRED but not found in PATH"
            else:
                status.message = f"{name} is OPTIONAL — some features disabled"
        else:
            status.message = f"{name} found at {path}"
        results.append(status)

    return results


def tool_available(name: str) -> bool:
    """Quick check if a specific tool is available."""
    return shutil.which(name) is not None
