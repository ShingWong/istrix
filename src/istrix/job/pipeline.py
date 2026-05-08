"""Job pipeline for managing scan execution and result tracking."""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from istrix.job.models import JobConfig, JobResult, JobManifest
from istrix.engine.scanner import ScanOrchestrator
from istrix.models.scan import ScanConfig
from istrix.reporting.generator import generate_report


DEFAULT_JOB_DIR = Path("./private/istrix-output/jobs")


class JobManager:
    """Manages the lifecycle of scan jobs: create, run, track, report."""

    def __init__(self, jobs_dir: str | Path | None = None):
        self.jobs_dir = Path(jobs_dir) if jobs_dir else DEFAULT_JOB_DIR
        self.jobs_dir.mkdir(parents=True, exist_ok=True)

    def create_job(
        self,
        targets: list[str],
        tier: str = "normal",
        name: str = "",
        customer_name: str = "",
        site_name: str = "",
        scan_notes: str = "",
        report_levels: list[str] | None = None,
        report_formats: list[str] | None = None,
        output_dir: str | None = None,
    ) -> JobManifest:
        """Create a new scan job."""
        job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        config = JobConfig(
            id=job_id,
            name=name or f"Scan {', '.join(targets[:2])}",
            targets=targets,
            tier=tier,
            output_dir=output_dir or str(self.jobs_dir.parent),
            customer_name=customer_name,
            site_name=site_name,
            scan_notes=scan_notes,
            report_levels=report_levels or ["detail"],
            report_formats=report_formats or ["html"],
        )
        manifest = JobManifest(config=config, result=None)
        self._save_manifest(manifest)
        return manifest

    def run_job(self, job_id: str) -> JobManifest:
        """Execute a pending job: run scan, generate reports."""
        manifest = self._load_manifest(job_id)
        if manifest is None:
            raise ValueError(f"Job not found: {job_id}")

        result = JobResult(
            job_id=job_id,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        manifest.result = result
        self._save_manifest(manifest)

        start = time.monotonic()

        try:
            scan_config = ScanConfig(
                tier=manifest.config.tier,
                targets=manifest.config.targets,
                verbose=False,
            )

            print(f"[cyan]Running scan:[/cyan] tier={manifest.config.tier} targets={manifest.config.targets}")
            orchestrator = ScanOrchestrator(scan_config)
            scan_result = orchestrator.run()

            elapsed = time.monotonic() - start

            output_dir = Path(manifest.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            results_path = output_dir / f"{job_id}_results.json"

            findings_data = [f.model_dump() for f in scan_result.findings]
            with open(results_path, "w") as f:
                json.dump({
                    "version": "0.1.0",
                    "summary": scan_result.summary(),
                    "config": scan_config.model_dump(),
                    "findings": findings_data,
                    "errors": scan_result.errors,
                }, f, indent=2, default=str)

            sev_counts = {"critical": 0, "high": 0}
            for f in scan_result.findings:
                if f.severity in sev_counts:
                    sev_counts[f.severity] += 1

            result.status = "completed"
            result.results_path = str(results_path)
            result.findings_count = len(scan_result.findings)
            result.critical_count = sev_counts["critical"]
            result.high_count = sev_counts["high"]
            result.finished_at = datetime.now(timezone.utc).isoformat()
            result.duration_seconds = round(elapsed, 1)

            print(f"[green]Scan complete:[/green] {result.findings_count} findings ({result.critical_count}C/{result.high_count}H) in {elapsed:.0f}s")

            for level in manifest.config.report_levels:
                for fmt in manifest.config.report_formats:
                    try:
                        report_path = generate_report(
                            results_paths=[str(results_path)],
                            level=level,
                            output_format=fmt,
                            output_dir=str(output_dir),
                            customer_name=manifest.config.customer_name,
                            site_name=manifest.config.site_name,
                            scan_notes=manifest.config.scan_notes,
                        )
                        result.reports.append(str(report_path))
                        print(f"[green]Report:[/green] {report_path}")
                    except ImportError:
                        pass
                    except Exception as e:
                        print(f"[yellow]Report {level}/{fmt} skipped:[/yellow] {e}")

            manifest.result = result
            self._save_manifest(manifest)
            return manifest

        except Exception as e:
            elapsed = time.monotonic() - start
            result.status = "failed"
            result.error = str(e)
            result.finished_at = datetime.now(timezone.utc).isoformat()
            result.duration_seconds = round(elapsed, 1)
            manifest.result = result
            self._save_manifest(manifest)
            print(f"[red]Job failed:[/red] {e}")
            return manifest

    def list_jobs(self) -> list[JobManifest]:
        """List all jobs."""
        manifests = []
        for f in sorted(self.jobs_dir.glob("*.json"), reverse=True):
            m = self._load_manifest(f.stem)
            if m:
                manifests.append(m)
        return manifests

    def get_job(self, job_id: str) -> JobManifest | None:
        """Get a specific job by ID."""
        return self._load_manifest(job_id)

    def _manifest_path(self, job_id: str) -> Path:
        return self.jobs_dir / f"{job_id}.json"

    def _save_manifest(self, manifest: JobManifest):
        path = self._manifest_path(manifest.config.id)
        data = manifest.model_dump()
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _load_manifest(self, job_id: str) -> JobManifest | None:
        path = self._manifest_path(job_id)
        if not path.exists():
            return None
        with open(path) as f:
            data = json.load(f)
        return JobManifest(**data)
