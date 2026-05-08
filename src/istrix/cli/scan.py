"""istrix scan command — run tiered network scans."""

import json
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text

from istrix.engine.nmap import nmap_available
from istrix.engine.scanner import ScanOrchestrator
from istrix.models.scan import ScanConfig

console = Console()

_progress_state = {"hosts_done": 0, "ports_found": 0, "findings": 0, "last_host": ""}


def scan_command(
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, or CIDRs to scan"),
    tier: str = typer.Option("normal", "--tier", "-t", help="Scan tier: quick, normal, full, aggressive, stealth"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Export results to JSON file (saves incrementally)"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, summary"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed scan progress"),
    parallel: int = typer.Option(1, "--parallel", "-p", help="Number of parallel scan workers (default: 1)"),
    resume: bool = typer.Option(False, "--resume", "-r", help="Resume from a partial scan file (requires --output)"),
    forest: bool = typer.Option(False, "--forest", help="Auto-discover AD forest subnets via DNS and scan all"),
    adaptive: bool = typer.Option(False, "--adaptive", help="Auto-tune parallel workers via benchmark sample"),
):
    """Run a tiered nmap scan against target hosts.

    Use --output for incremental saving (survives disconnects).
    Use --resume with --output to continue a partially completed scan.

    Examples:
        istrix scan 192.168.1.1 --tier quick
        istrix scan example.com --tier full -o results.json
        istrix scan 10.0.0.0/24 --tier stealth -f summary
        istrix scan 10.0.0.0/24 --tier quick --parallel 20 -o results.json
        istrix scan 10.0.0.0/24 --tier aggressive -o results.json --resume
    """
    _check_prerequisites()

    incremental_path = output if output else None

    if resume and not output:
        console.print("[red]Error:[/red] --resume requires --output to specify the partial scan file")
        raise typer.Exit(code=1)

    config = ScanConfig(
        tier=tier,
        targets=targets,
        output_file=str(output) if output else None,
        verbose=verbose,
    )

    _show_banner(config)

    target_count = len(targets)
    try:
        from istrix.models.target import expand_targets
        target_count = len(expand_targets(targets))
    except Exception:
        pass

    if parallel > 1:
        console.print(f"[dim]Starting scan with [bold]{parallel}[/bold] parallel workers, [bold]{target_count}[/bold] targets...[/dim]")
    elif adaptive and target_count > 5:
        parallel = _auto_tune_workers(targets, tier, target_count)
    else:
        console.print(f"[dim]Starting scan of [bold]{target_count}[/bold] target(s)...[/dim]")

    start = time.monotonic()

    orch = ScanOrchestrator(
        config,
        max_workers=parallel,
        incremental_path=incremental_path,
    )

    if parallel > 1 and target_count > 1:
        result = _run_with_progress(config, parallel, target_count, output, orch)
    else:
        result = orch.run()

    elapsed = time.monotonic() - start

    _display_results(result, output_format, elapsed)

    if output:
        # Final save over the incremental file with completed state
        _export_json(result, output)

    # Forest expansion: auto-discover other subnets via DNS and scan them
    if forest and output:
        _expand_forest_scan(targets, tier, output, parallel, config)


def _expand_forest_scan(initial_targets, tier_name, output_path, parallel, _config):
    """Discover AD forest subnets via DNS and scan each incrementally.

    After each subnet completes:
      - HTML reports are generated immediately
      - Results merged into the master file
      - Index page updated
    """
    import shutil
    import re

    # Determine subnet prefix from initial targets (e.g., /24 from 10.0.0.0/24)
    prefix = 24  # default
    for t in initial_targets:
        if "/" in t:
            try:
                prefix = int(t.split("/")[1])
                break
            except (ValueError, IndexError):
                pass
    import subprocess as _subprocess

    if not shutil.which("dig"):
        console.print("[yellow]Forest mode requires `dig`[/yellow]")
        return

    # 1. Find DNS server and domain from initial results
    with open(output_path) as f:
        data = json.load(f)
    dns_server = ""
    domain = ""
    for finding in data.get("findings", []):
        if finding.get("type") == "service" and finding.get("port") == 53:
            # Prefer DNS server on a DC (has LDAP or Kerberos)
            host = finding.get("host", "")
            host_findings = [f for f in data.get("findings", []) if f.get("host") == host]
            is_dc = any(
                "ldap" in (f.get("detail", "")).lower() or
                "kerberos" in (f.get("detail", "")).lower()
                for f in host_findings
            )
            if is_dc and not dns_server:
                dns_server = host
            elif not dns_server:
                dns_server = host  # fallback
        m = re.search(r'Domain:\s*(\S+)', finding.get("detail", ""))
        if m and not domain:
            domain = m.group(1).rstrip(".,;0")
    # fallback: extract domain from hostname of DNS server
    if not domain and dns_server:
        for finding in data.get("findings", []):
            if finding.get("host") == dns_server and finding.get("type") in ("dns", "os"):
                m = re.search(r'Hostname:\s*[^.]+\.(.+)', finding.get("detail", ""))
                if m:
                    domain = m.group(1).rstrip(".,;0")
                    break
    if not dns_server:
        console.print("[yellow]No DNS server found — skipping forest[/yellow]")
        return
    if not domain:
        console.print("[yellow]No domain found — skipping forest[/yellow]")
        return

    # 2. Discover subnets via DNS SRV
    console.print(f"\n[bold cyan]Forest Discovery[/bold cyan] via DNS {dns_server}...")
    dc_ips: dict[str, str] = {}
    for suffix in ("_ldap._tcp", "_kerberos._tcp", "_gc._tcp"):
        try:
            r = _subprocess.run(
                ["dig", f"@{dns_server}", f"{suffix}.{domain}", "SRV", "+short", "+time=2"],
                capture_output=True, text=True, timeout=10)
            for line in r.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 4 and parts[3].rstrip(".") not in dc_ips:
                    hostname = parts[3].rstrip(".")
                    r2 = _subprocess.run(
                        ["dig", f"@{dns_server}", hostname, "A", "+short", "+time=2"],
                        capture_output=True, text=True, timeout=10)
                    ip = r2.stdout.strip()
                    if ip and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        dc_ips[hostname] = ip
        except Exception:
            continue

    if not dc_ips:
        console.print("[yellow]No DCs discovered via DNS[/yellow]")
        return

    subnets: dict[str, str] = {}
    for hostname, ip in dc_ips.items():
        parts = ip.split(".")
        sn = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
        site = hostname.split(".")[0]
        subnets[sn] = site

    # Fallback: also extract subnets from dns_probe findings
    # (catches decommissioned DCs still resolvable via PTR)
    for finding in data.get("findings", []):
        if finding.get("type") != "dns":
            continue
        detail = finding.get("detail", "")
        if "→" in detail:
            for segment in re.findall(r'(\S+→(\d+\.\d+\.\d+)\.\d+)', detail):
                hostname = segment[0].split("→")[0].strip()
                ip_parts = segment[1]
                parts = ip_parts.split(".")
                sn = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
                if sn not in subnets:
                    site = hostname.split(".")[0]
                    subnets[sn] = site
        if "Hostname:" in detail:
            m = re.search(r'Hostname:\s*dc[^.]*\.(.+)', detail)
            if m and m.group(1).count(".") >= 2:
                host = finding.get("host", "")
                if host:
                    parts = host.split(".")
                    if len(parts) == 4:
                        sn = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
                        if sn not in subnets:
                            subnets[sn] = m.group(1).split(".")[0]

    console.print(f"\n[green]{len(subnets)} subnets discovered:[/green]")
    for sn, site in sorted(subnets.items()):
        console.print(f"  {sn:20s} ({site})")

    # 3. Scan each subnet incrementally, with resume support
    completed_subnets = set(data.get("_forest_completed", []))
    scanned = set(f.get("host", "") for f in data.get("findings", []))
    from istrix.models.target import expand_targets

    for i, (sn, site) in enumerate(sorted(subnets.items()), 1):
        if sn in completed_subnets:
            console.print(f"[dim]  {sn} ({site}): already completed[/dim]")
            continue

        # Build unscanned targets for this subnet
        sn_ips = [ip for ip in expand_targets([sn]) if ip not in scanned]
        if not sn_ips:
            console.print(f"[dim]  {sn} ({site}): all already scanned[/dim]")
            completed_subnets.add(sn)
            data["_forest_completed"] = sorted(completed_subnets)
            with open(output_path, "w") as f:
                json.dump(data, f, default=str, indent=2)
            continue

        console.print(f"\n[bold]Subnet {i}/{len(subnets)}: {sn} ({site})[/bold] — {len(sn_ips)} targets")

        # Use a per-subnet incremental file for resume safety
        subnet_json = Path(f"{output_path.parent / site}.json" if hasattr(output_path, "parent")
                           else Path(f"results_{site}.json"))
        config = ScanConfig(tier=tier_name, targets=sn_ips)
        orch = ScanOrchestrator(config, max_workers=parallel,
                                incremental_path=subnet_json)
        result = orch.run()

        # Save this subnet's results
        _export_json(result, subnet_json)

        # Merge into master
        with open(subnet_json) as f:
            sn_data = json.load(f)
        sn_hosts = set(f.get("host", "") for f in sn_data.get("findings", []))
        scanned.update(sn_hosts)
        data["findings"].extend(sn_data.get("findings", []))
        data["scanned_hosts"] = sorted(set(
            f.get("host", "") for f in data["findings"] if f.get("host")
        ))
        data["summary"] = {
            "hosts_scanned": len(data["scanned_hosts"]),
            "total_findings": len(data["findings"]),
        }
        completed_subnets.add(sn)
        data["_forest_completed"] = sorted(completed_subnets)
        with open(output_path, "w") as f:
            json.dump(data, f, default=str, indent=2)

        console.print(f"  [green]{len(sn_hosts)} hosts, {sn_data.get('summary', {}).get('total_findings', 0)} findings[/green]")

    console.print(f"\n[bold green]Forest scan complete. {len(scanned)} total hosts in {output_path}[/bold green]")


def _run_with_progress(config, parallel, total, output_path, orch=None):
    """Run scan with Rich progress bar, incremental saving."""
    result = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[host]}[/dim]"),
        TextColumn("[dim]{task.fields[stats]}[/dim]"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Scanning[/cyan]",
            total=total,
            host="",
            stats="",
        )

        def on_progress(completed, total_h, host, findings_count):
            progress.update(
                task,
                completed=completed,
                host=f"Host: {host}",
                stats=f"±{findings_count} findings"
            )

        if orch is None:
            orch = ScanOrchestrator(config, max_workers=parallel,
                                    progress_callback=on_progress,
                                    incremental_path=output_path)
        else:
            orch.progress_callback = on_progress
        result = orch.run()

    return result

    if result.errors:
        console.print()
        for err in result.errors:
            console.print(f"[red]  Error:[/red] {err}")


def _check_prerequisites():
    errors = []
    if not nmap_available():
        errors.append("[red]nmap is not installed.[/red] Install it with: apt install nmap")
    # nmap.py auto-detects sudoers and uses privileged mode if available
    if errors:
        for err in errors:
            console.print(err)
        raise typer.Exit(code=1)
    console.print()


def _show_banner(config: ScanConfig):
    targets_str = ", ".join(config.targets[:3])
    if len(config.targets) > 3:
        targets_str += f" (+{len(config.targets) - 3} more)"
    console.print()
    console.print(Panel.fit(
        f"[bold]Targets:[/bold] {targets_str}\n[bold]Tier:[/bold] [cyan]{config.tier}[/cyan]",
        title="[bold]iStrix Scan[/bold]",
        border_style="cyan",
    ))


def _display_results(result, fmt: str, elapsed: float):
    findings = result.findings
    summary_result = result.summary()

    if fmt == "json":
        data = {
            "summary": summary_result,
            "elapsed_seconds": round(elapsed, 1),
            "findings": [f.model_dump() for f in findings],
        }
        console.print_json(data=json.dumps(data, indent=2))
        return

    if fmt == "summary":
        _display_summary(result, elapsed)
        return

    _display_table(findings, summary_result, elapsed)


def _display_summary(result, elapsed: float):
    summary_result = result.summary()
    title = Text("Scan Complete", style="bold green")
    console.print()
    console.print(Panel.fit(
        f"[bold]Duration:[/bold] {elapsed:.1f}s\n"
        f"[bold]Hosts scanned:[/bold] {summary_result['hosts_scanned']}\n"
        f"[bold]Open ports:[/bold] {summary_result['ports_open']}\n"
        f"[bold]Total findings:[/bold] {summary_result['total_findings']}",
        title=title,
        border_style="green",
    ))
    if summary_result["by_severity"]:
        sev_text = "  ".join(
            f"[{_sev_color(s)}]{s}[/{_sev_color(s)}]: {c}"
            for s, c in sorted(
                summary_result["by_severity"].items(),
                key=lambda x: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(x[0], 0),
                reverse=True,
            )
        )
        console.print(f"  {sev_text}")
        console.print()


def _display_table(findings, summary_result: dict, elapsed: float):
    title = Text(f"Scan Results ({len(findings)} findings, {elapsed:.1f}s)", style="bold cyan")
    console.print()

    if not findings:
        console.print("[yellow]No findings to display.[/yellow]")
        return

    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Host", style="dim", width=18)
    table.add_column("Port", width=7, justify="right")
    table.add_column("Proto", width=5)
    table.add_column("Finding", width=50)
    table.add_column("Severity", width=10)

    for f in findings[:100]:
        host = f.host[:17]
        port = str(f.port) if f.port is not None else "-"
        proto = f.protocol or "-"
        detail = f.detail[:49]
        sev = f.severity
        table.add_row(host, port, proto, detail, f"[{_sev_color(sev)}]{sev}[/{_sev_color(sev)}]")

    console.print(table)

    if len(findings) > 100:
        console.print(f"[dim]  ... and {len(findings) - 100} more findings[/dim]")

    console.print()
    _display_summary_line(summary_result, elapsed)


def _display_summary_line(summary_result: dict, elapsed: float):
    parts = [
        f"[dim]{elapsed:.1f}s[/dim]",
        f"{summary_result['hosts_scanned']} hosts",
        f"{summary_result['ports_open']} ports",
        f"{summary_result['total_findings']} findings",
    ]
    if summary_result["by_severity"]:
        sev_parts = "  ".join(
            f"[{_sev_color(s)}]{c} {s}[/{_sev_color(s)}]"
            for s, c in sorted(
                summary_result["by_severity"].items(),
                key=lambda x: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(x[0], 0),
                reverse=True,
            )
        )
        parts.append(sev_parts)
    console.print("  " + "  |  ".join(parts))


def _auto_tune_workers(targets: list[str], tier: str, target_count: int) -> int:
    """Benchmark 10-host sample at increasing worker counts to find optimal."""
    import subprocess as _subprocess
    from istrix.models.target import expand_targets

    # Expand and sample first 10 IPs
    all_targets = expand_targets(targets)
    sample = all_targets[:10]

    if tier == "quick":
        candidate_counts = [15, 20, 25, 30]
    elif tier in ("full", "aggressive"):
        candidate_counts = [4, 6, 8, 10, 12]
    else:
        candidate_counts = [8, 12, 16, 20]

    best_workers = candidate_counts[0]
    max_safe_sockets = 30_000
    max_safe_cpu = 85.0

    console.print(f"\n[bold cyan]Adaptive Worker Tuning[/bold cyan] — testing {len(sample)} hosts at {len(candidate_counts)} worker counts")
    console.print(f"[dim]Max safe: {max_safe_sockets:,} sockets, {max_safe_cpu:.0f}% CPU[/dim]\n")

    for count in candidate_counts:
        if count > target_count:
            count = max(1, target_count // 2)
            if count in candidate_counts:
                continue

        # Run benchmark: scan 10 hosts with `count` workers for 15s
        try:
            proc = _subprocess.Popen(
                ["istrix", "scan", *sample, "--tier", "quick",
                 "--parallel", str(count), "-f", "summary"],
                stdout=_subprocess.PIPE, stderr=_subprocess.PIPE,
                text=True,
            )

            peak_sockets = 0
            peak_cpu = 0.0
            deadline = time.monotonic() + 20

            while time.monotonic() < deadline and proc.poll() is None:
                # Measure sockets
                try:
                    r = _subprocess.run(["ss", "-s"], capture_output=True, text=True, timeout=2)
                    import re as _re
                    m = _re.search(r"Total:\s+(\d+)", r.stdout)
                    if m:
                        sock = int(m.group(1))
                        if sock > peak_sockets:
                            peak_sockets = sock
                except Exception:
                    pass

                # Measure CPU
                try:
                    r = _subprocess.run(["top", "-bn1"], capture_output=True, text=True, timeout=2)
                    m = _re.search(r"(\d+\.?\d*)\s*id", r.stdout)
                    if m:
                        cpu = 100.0 - float(m.group(1))
                        if cpu > peak_cpu:
                            peak_cpu = cpu
                except Exception:
                    pass

                time.sleep(1.5)

            proc.terminate()
            try:
                proc.wait(timeout=5)
            except _subprocess.TimeoutExpired:
                proc.kill()

            safe = "✓" if peak_sockets < max_safe_sockets and peak_cpu < max_safe_cpu else "✗"
            console.print(
                f"  [dim]workers={count:3d}[/dim]  "
                f"sockets={peak_sockets:>6,}  cpu={peak_cpu:>5.1f}%  {safe}"
            )

            if peak_sockets < max_safe_sockets and peak_cpu < max_safe_cpu:
                best_workers = count
            else:
                break  # stop at first unsafe count

        except Exception as e:
            console.print(f"  [dim]workers={count:3d}[/dim]  [red]benchmark failed: {e}[/red]")
            continue

    console.print(f"\n[bold green]Selected: {best_workers} workers[/bold green]")
    console.print(f"[dim]Starting scan with [bold]{best_workers}[/bold] parallel workers, [bold]{target_count}[/bold] targets...[/dim]")
    return best_workers


def _export_json(result, path: Path):
    # Build findings from result
    result_findings = [f.model_dump() for f in result.findings]
    # Preserve forest expansion progress and merge with existing findings on resume
    forest_completed = None
    if path.exists():
        try:
            prior = json.loads(path.read_text())
            if "_forest_completed" in prior:
                forest_completed = prior["_forest_completed"]
            # Merge prior findings not already in result_findings (prevents dict→Finding round-trip loss)
            existing_keys = {(fd.get("host"), fd.get("port"), fd.get("type"), fd.get("detail"))
                             for fd in result_findings}
            for fd in prior.get("findings", []):
                key = (fd.get("host"), fd.get("port"), fd.get("type"), fd.get("detail"))
                if key not in existing_keys:
                    result_findings.append(fd)
                    existing_keys.add(key)
        except (json.JSONDecodeError, OSError):
            pass
    data = {
        "version": "0.1.0",
        "summary": result.summary(),
        "config": result.config.model_dump(),
        "findings": result_findings,
        "errors": result.errors,
        "scanned_hosts": sorted({f["host"] for f in result_findings if f.get("host")}),
        "last_updated": result.finished_at or "",
    }
    if forest_completed:
        data["_forest_completed"] = forest_completed
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]Results exported to {path}[/green]")


def _sev_color(severity: str) -> str:
    colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green", "info": "dim"}
    return colors.get(severity, "white")
