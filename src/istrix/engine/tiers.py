"""Scan tier configuration loader."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

ScanIntensity = Literal["passive", "active", "intrusive"]


class TierConfig(BaseModel):
    """Configuration for a single scan tier."""

    name: str
    label: str
    description: str = ""
    nmap_flags: str = "-sS -T4 -F"
    follow_up: list[str] = Field(default_factory=list)
    timeout: int = 300
    intensity: ScanIntensity = "active"


DEFAULT_TIERS_PATH = Path(__file__).parent.parent.parent.parent / "config" / "tiers.yaml"


def load_tiers(path: str | Path | None = None) -> dict[str, TierConfig]:
    """Load tier definitions from a YAML file.

    Args:
        path: Path to tiers.yaml. Defaults to config/tiers.yaml relative to project root.

    Returns:
        Dict mapping tier name to TierConfig.

    Raises:
        FileNotFoundError: If the tiers file doesn't exist.
        ValueError: If the YAML is malformed or missing the 'tiers' key.
    """
    filepath = Path(path) if path else DEFAULT_TIERS_PATH

    if not filepath.exists():
        raise FileNotFoundError(f"Tier configuration not found: {filepath}")

    with open(filepath) as f:
        data = yaml.safe_load(f)

    if not data or "tiers" not in data:
        raise ValueError(f"Invalid tiers file: missing 'tiers' key in {filepath}")

    result: dict[str, TierConfig] = {}
    for name, cfg in data["tiers"].items():
        result[name] = TierConfig(name=name, **cfg)

    return result


def get_tier(name: str, path: str | Path | None = None) -> TierConfig:
    """Get a specific tier configuration by name.

    Args:
        name: Tier name (quick, normal, full, aggressive, stealth)
        path: Optional custom tiers file path.

    Returns:
        TierConfig for the requested tier.

    Raises:
        ValueError: If the tier name is not found.
    """
    tiers = load_tiers(path)
    if name not in tiers:
        available = ", ".join(sorted(tiers.keys()))
        raise ValueError(
            f"Unknown tier '{name}'. Available tiers: {available}"
        )
    return tiers[name]


def list_tiers(path: str | Path | None = None) -> list[TierConfig]:
    """Return all available tier configurations sorted by intensity."""
    tiers = load_tiers(path)
    intensity_order = {"passive": 0, "active": 1, "intrusive": 2}
    return sorted(
        tiers.values(),
        key=lambda t: intensity_order.get(t.intensity, 99),
    )
