"""Scan orchestration engine for iStrix."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from istrix.engine.modules import MODULE_REGISTRY
from istrix.engine.modules.base import ScanModule
from istrix.engine.nmap import run_nmap, nmap_available
from istrix.engine.tiers import get_tier, TierConfig
from istrix.models.finding import Finding
from istrix.models.scan import ScanConfig, ScanResult
from istrix.models.target import expand_targets
from istrix.utils.deps import tool_available


class ScanOrchestrator:
    """Orchestrates a complete tiered scan across multiple targets.

    Supports parallel execution via ThreadPoolExecutor for /24+ subnets.
    Supports incremental save/resume for long-running scans.
    """

    def __init__(self, config: ScanConfig, max_workers: int = 1,
                 progress_callback=None, incremental_path: Path | None = None):
        self.config = config
        self.max_workers = max_workers
        self.progress_callback = progress_callback
        self.incremental_path = incremental_path
        self._errors: list[str] = []
        self._warnings: list[str] = []
        self._lock = threading.Lock()
        self._start_time = 0.0
        self._scanned_hosts: set[str] = set()
        self._prior_findings: list[dict] = []

        if self.incremental_path and self.incremental_path.exists():
            prior = self._load_incremental(self.incremental_path)
            if prior:
                self._scanned_hosts = set(prior.get("scanned_hosts", []))
                self._prior_findings = prior.get("findings", [])

    def run(self) -> ScanResult:
        """Execute the full scan pipeline. Uses parallel workers if max_workers > 1."""
        result = ScanResult(config=self.config)
        result.started_at = datetime.now(timezone.utc).isoformat()
        self._start_time = time.monotonic()

        if not nmap_available():
            self._errors.append("nmap is not installed. Cannot run scan.")
            result.errors = self._errors
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        tier = self._load_tier()
        if tier is None:
            result.errors = self._errors
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        targets = expand_targets(self.config.targets)

        pending = [t for t in targets if t not in self._scanned_hosts]
        if len(pending) < len(targets):
            self._log(f"Resuming — {len(pending)} of {len(targets)} hosts remaining")

        total = len(targets)

        # Restore prior findings so incremental saves and final result preserve them
        prior_findings: list[Finding] = []
        for fd in self._prior_findings:
            try:
                prior_findings.append(Finding(**fd))
            except Exception:
                pass

        if self.max_workers > 1 and total > 1:
            new_findings = self._run_parallel(pending, tier, total)
            all_findings = prior_findings + new_findings
        else:
            all_findings = list(prior_findings)
            for i, target in enumerate(pending):
                findings = self._scan_target(target, tier)
                all_findings.extend(findings)
                current = len(self._scanned_hosts)
                if self.progress_callback:
                    self.progress_callback(current, total, target, len(findings))
                self._save_incremental(result, all_findings, current)

        all_findings = self._deduplicate(all_findings)

        if self.config.verbose:
            all_findings.sort(key=lambda f: (-f.severity_rank(), f.host, f.port or 0))

        result.findings = all_findings
        result.errors = self._errors
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result

    def _run_parallel(self, targets: list[str], tier: TierConfig, total: int) -> list[Finding]:
        """Run scans in parallel using a thread pool."""
        all_findings: list[Finding] = []
        completed = len(self._scanned_hosts)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(self._scan_target, t, tier): t for t in targets}

            for future in as_completed(future_map):
                target = future_map[future]
                try:
                    findings = future.result()
                    with self._lock:
                        all_findings.extend(findings)
                        completed += 1
                except Exception as e:
                    with self._lock:
                        self._errors.append(f"nmap error on {target}: {e}")
                        completed += 1

                if self.progress_callback:
                    try:
                        self.progress_callback(completed, total, target, len(findings))
                    except NameError:
                        self.progress_callback(completed, total, target, 0)

                if self.incremental_path:
                    with self._lock:
                        self._save_incremental_sync(all_findings, completed)

        return all_findings

    def _save_incremental(self, result: ScanResult, findings: list[Finding],
                          completed_count: int) -> None:
        """Save incremental progress to the partial JSON file (thread-safe wrapper)."""
        if not self.incremental_path:
            return
        with self._lock:
            self._save_incremental_sync(findings, completed_count)

    def _save_incremental_sync(self, findings: list[Finding],
                                completed_count: int) -> None:
        """Write incremental state to disk. Caller must hold self._lock."""
        if not self.incremental_path:
            return
        # Merge prior findings with new findings, dedup by (host, port, type, detail)
        seen = set()
        merged = []
        for fd in self._prior_findings:
            key = (fd.get("host"), fd.get("port"), fd.get("type"), fd.get("detail"))
            if key not in seen:
                seen.add(key)
                merged.append(fd)
        new_fds = [f.model_dump() for f in findings]
        for fd in new_fds:
            key = (fd.get("host"), fd.get("port"), fd.get("type"), fd.get("detail"))
            if key not in seen:
                seen.add(key)
                merged.append(fd)
        # Preserve forest expansion progress across sessions
        forest = {}
        if self.incremental_path.exists():
            try:
                prior = json.loads(self.incremental_path.read_text())
                if "_forest_completed" in prior:
                    forest["_forest_completed"] = prior["_forest_completed"]
            except (json.JSONDecodeError, OSError):
                pass
        data = {
            "version": "0.1.0",
            "config": self.config.model_dump(),
            "findings": merged,
            "scanned_hosts": sorted(self._scanned_hosts),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "errors": self._errors,
            **forest,
        }
        tmp = self.incremental_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.rename(self.incremental_path)

    @staticmethod
    def _load_incremental(path: Path) -> dict | None:
        """Load previously saved incremental scan state."""
        try:
            data = json.loads(path.read_text())
            if data.get("version") and data.get("findings") is not None:
                return data
        except (json.JSONDecodeError, OSError):
            pass
        return None

    @staticmethod
    def resume_available(path: Path) -> bool:
        """Check if a partial scan file exists and has valid state."""
        if not path.exists():
            return False
        return ScanOrchestrator._load_incremental(path) is not None

    def _on_target_complete(self, target: str):
        """Called after each target finishes (within lock in parallel mode)."""
        self._scanned_hosts.add(target)

    def _load_tier(self) -> TierConfig | None:
        try:
            return get_tier(self.config.tier)
        except ValueError as e:
            self._errors.append(str(e))
            return None
        except FileNotFoundError as e:
            self._errors.append(str(e))
            return None

    def _scan_target(self, target: str, tier: TierConfig) -> list[Finding]:
        """Run the scan pipeline for a single target."""
        all_findings: list[Finding] = []

        self._log(f"Scanning {target} with tier '{tier.name}' ({tier.label})")
        start = time.monotonic()

        try:
            nmap_findings = run_nmap(
                target=target,
                flags=tier.nmap_flags,
                timeout=tier.timeout,
            )
            all_findings.extend(nmap_findings)
            self._log(f"  nmap complete: {len(nmap_findings)} findings")
        except FileNotFoundError as e:
            self._errors.append(str(e))
            return all_findings
        except Exception as e:
            self._errors.append(f"nmap error on {target}: {e}")
            return all_findings

        for module_name in tier.follow_up:
            module = self._get_module(module_name)
            if module is None:
                continue

            try:
                module_results = module.run(all_findings)
                all_findings.extend(module_results)
                self._log(f"  {module_name} complete: {len(module_results)} findings")
            except Exception as e:
                self._errors.append(f"Module {module_name} error: {e}")

        elapsed = time.monotonic() - start
        self._log(f"  Finished {target} in {elapsed:.1f}s")
        self._on_target_complete(target)

        return all_findings

    def _get_module(self, name: str) -> ScanModule | None:
        """Get a module instance by name from the registry."""
        if name not in MODULE_REGISTRY:
            self._warnings.append(f"Unknown module: {name}")
            return None
        module = MODULE_REGISTRY[name]()
        if not module.optional:
            return module
        required_tool = self._module_tool_map.get(name)
        if required_tool and not tool_available(required_tool):
            self._warnings.append(
                f"Module '{name}' skipped: {required_tool} not installed"
            )
            return None
        return module

    _module_tool_map: dict[str, str] = {
        "http_probe": "whatweb",
    }

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings based on dedup key."""
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in findings:
            key = f.dedup_key()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _log(self, message: str):
        if self.config.verbose:
            print(message)
