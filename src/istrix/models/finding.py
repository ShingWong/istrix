"""Normalized finding model consumed and produced by all scan modules."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
FindingType = Literal[
    "open_port",
    "service",
    "os",
    "vulnerability",
    "web_tech",
    "certificate",
    "dns",
    "credential",
    "printer",
    "other",
]


class Finding(BaseModel):
    """A normalized security finding from any scan module."""

    type: FindingType
    host: str = Field(..., description="Target IP address or hostname")
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, pattern="^(tcp|udp)$")
    detail: str = Field(..., description="Human-readable description")
    severity: FindingSeverity = Field(default="info")
    source: str = Field(..., description="Tool that produced this finding")
    cve: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    evidence: str | None = Field(default=None, description="Raw output snippet")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def is_vulnerability(self) -> bool:
        """Returns True if this finding indicates a vulnerability."""
        return self.type == "vulnerability" or self.cve is not None

    def dedup_key(self) -> str:
        """Return a unique key for deduplication."""
        return f"{self.host}:{self.port}:{self.type}:{self.detail[:50]}"

    def severity_rank(self) -> int:
        """Return numeric rank for sorting (higher = more severe)."""
        ranks = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return ranks.get(self.severity, 0)
