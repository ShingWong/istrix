"""JSON import/export for iStrix scan results."""

import json
from pathlib import Path

from istrix.models.finding import Finding
from istrix.models.scan import ScanResult, ScanConfig


def export_to_json(result: ScanResult, path: str | Path):
    """Export scan results to a JSON file."""
    data = {
        "version": "0.1.0",
        "config": result.config.model_dump(),
        "summary": result.summary(),
        "findings": [f.model_dump() for f in result.findings],
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "errors": result.errors,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def load_from_json(path: str | Path) -> ScanResult:
    """Load scan results from a JSON file."""
    with open(path) as f:
        data = json.load(f)

    config = ScanConfig(**data["config"])
    findings = [Finding(**f) for f in data["findings"]]
    errors = data.get("errors", [])

    result = ScanResult(
        config=config,
        findings=findings,
        errors=errors,
    )
    result.started_at = data.get("started_at", "")
    result.finished_at = data.get("finished_at", "")
    return result
