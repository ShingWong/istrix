"""Job models for scan pipeline management."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

JobStatus = Literal["pending", "running", "completed", "failed", "cancelled"]


class JobConfig(BaseModel):
    """Configuration for a scan job."""

    id: str = Field(..., description="Unique job ID")
    name: str = Field(default="", description="Human-readable job name")
    targets: list[str] = Field(..., min_length=1)
    tier: str = Field(default="normal")
    output_dir: str = Field(default="./private/istrix-output")
    customer_name: str = Field(default="")
    site_name: str = Field(default="")
    scan_notes: str = Field(default="")
    report_levels: list[str] = Field(default_factory=lambda: ["detail"])
    report_formats: list[str] = Field(default_factory=lambda: ["html"])
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class JobResult(BaseModel):
    """Result of a completed or failed job."""

    job_id: str
    status: JobStatus
    results_path: str | None = None
    reports: list[str] = Field(default_factory=list)
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float | None = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0

    def summary_line(self) -> str:
        if self.status == "failed":
            return f"[red]FAILED[/red] {self.job_id}: {self.error}"
        return (
            f"[green]DONE[/green] {self.job_id} "
            f"({self.duration_seconds:.0f}s) "
            f"[dim]{self.findings_count} findings[/dim] "
            f"[red]{self.critical_count}C[/red] "
            f"[yellow]{self.high_count}H[/yellow]"
        )


class JobManifest(BaseModel):
    """Full manifest for a job including config and results."""

    config: JobConfig
    result: JobResult | None = None
