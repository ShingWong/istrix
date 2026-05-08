"""Scan configuration and result models."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from istrix.models.finding import Finding


ScanIntensity = Literal["passive", "active", "intrusive"]


class ScanConfig(BaseModel):
    """Configuration for a single scan run."""

    tier: str = Field(..., description="Scan tier: quick, normal, full, aggressive, stealth")
    targets: list[str] = Field(..., min_length=1, description="Target IPs, hosts, or CIDRs")
    output_file: str | None = Field(default=None, description="JSON output path")
    verbose: bool = Field(default=False)


class ScanResult(BaseModel):
    """Complete result from a scan run."""

    config: ScanConfig
    findings: list[Finding] = Field(default_factory=list)
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str | None = None
    errors: list[str] = Field(default_factory=list)

    def summary(self) -> dict:
        """Return a summary dict with counts by severity and type."""
        sev_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        hosts: set[str] = set()
        ports: set[str] = set()

        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            type_counts[f.type] = type_counts.get(f.type, 0) + 1
            hosts.add(f.host)
            if f.port is not None:
                ports.add(f"{f.host}:{f.port}")

        return {
            "total_findings": len(self.findings),
            "hosts_scanned": len(hosts),
            "ports_open": len(ports),
            "by_severity": sev_counts,
            "by_type": type_counts,
            "errors": len(self.errors),
        }
