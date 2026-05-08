"""istrix job command — manage scan jobs and pipelines."""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from istrix.job.pipeline import JobManager

console = Console()

job_app = typer.Typer(help="Manage scan jobs and pipelines", no_args_is_help=True)


@job_app.command()
def create(
    targets: list[str] = typer.Argument(..., help="Target IPs, hostnames, or CIDRs"),
    tier: str = typer.Option("normal", "--tier", "-t", help="Scan tier"),
    name: str = typer.Option("", "--name", help="Job name"),
    customer: str = typer.Option("", "--customer", "-c", help="Customer name for reports"),
    site: str = typer.Option("", "--site", "-s", help="Site name for reports"),
    notes: str = typer.Option("", "--notes", "-n", help="Scan notes"),
    report_level: str = typer.Option("detail", "--report-level", help="Report level: brief, detail, threat, remediation"),
    report_format: str = typer.Option("html", "--report-format", help="Report format: html, pdf, md"),
    output_dir: str = typer.Option("./private/istrix-output", "--output-dir", "-o", help="Output directory"),
):
    """Create a new scan job."""
    mgr = JobManager(Path(output_dir) / "jobs")
    manifest = mgr.create_job(
        targets=targets,
        tier=tier,
        name=name,
        customer_name=customer,
        site_name=site,
        scan_notes=notes,
        report_levels=[report_level],
        report_formats=[report_format],
        output_dir=output_dir,
    )
    console.print(f"[green]Job created:[/green] {manifest.config.id}")
    console.print(f"  Targets: {', '.join(targets)}")
    console.print(f"  Tier: {tier}")
    console.print(f"  Output: {output_dir}/")
    console.print()
    console.print(f"[dim]Run with: istrix job run {manifest.config.id}[/dim]")


@job_app.command()
def run(
    job_id: str = typer.Argument(..., help="Job ID to run"),
):
    """Execute a pending scan job."""
    mgr = JobManager()
    try:
        manifest = mgr.run_job(job_id)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    if manifest.result and manifest.result.status == "completed":
        console.print()
        console.print(Panel.fit(
            f"[bold green]Job Complete[/bold green]\n"
            f"Results: {manifest.result.results_path}\n"
            f"Reports: {len(manifest.result.reports)} generated\n"
            f"Findings: {manifest.result.findings_count} "
            f"([red]{manifest.result.critical_count}C[/red] "
            f"[yellow]{manifest.result.high_count}H[/yellow])",
            border_style="green",
        ))

        for r in manifest.result.reports:
            console.print(f"  [dim]• {r}[/dim]")
    elif manifest.result:
        console.print(f"[red]Job failed:[/red] {manifest.result.error}")


@job_app.command(name="list")
def list_cmd():
    """List all jobs and their status."""
    mgr = JobManager()
    jobs = mgr.list_jobs()

    if not jobs:
        console.print("[dim]No jobs found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Job ID", style="dim")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Targets")
    table.add_column("Findings")
    table.add_column("Created")

    for m in jobs[:20]:
        c = m.config
        r = m.result
        status = "[yellow]pending[/yellow]" if r is None else r.status
        if r and r.status == "completed":
            status = "[green]completed[/green]"
        elif r and r.status == "failed":
            status = "[red]failed[/red]"
        elif r and r.status == "running":
            status = "[cyan]running[/cyan]"

        findings = f"{r.findings_count}" if r else "-"
        created = c.created_at[:16] if c.created_at else "-"

        table.add_row(
            c.id[:20] + "...",
            c.name[:25],
            status,
            ", ".join(c.targets[:2])[:30],
            findings,
            created,
        )

    console.print(table)


@job_app.command()
def show(
    job_id: str = typer.Argument(..., help="Job ID to show"),
):
    """Show details for a specific job."""
    mgr = JobManager()
    manifest = mgr.get_job(job_id)

    if manifest is None:
        console.print(f"[red]Job not found:[/red] {job_id}")
        raise typer.Exit(code=1)

    c = manifest.config
    r = manifest.result

    console.print(Panel.fit(
        f"[bold]Job: {c.id}[/bold]\n"
        f"Name: {c.name}\n"
        f"Targets: {', '.join(c.targets)}\n"
        f"Tier: {c.tier}\n"
        f"Customer: {c.customer_name or 'N/A'}\n"
        f"Site: {c.site_name or 'N/A'}",
        title="Job Configuration",
    ))

    if r:
        status_color = {"completed": "green", "failed": "red", "running": "cyan"}.get(r.status, "yellow")
        console.print(Panel.fit(
            f"Status: [{status_color}]{r.status}[/{status_color}]\n"
            f"Duration: {r.duration_seconds:.1f}s\n"
            f"Findings: {r.findings_count} "
            f"([red]{r.critical_count}C[/red] [yellow]{r.high_count}H[/yellow])\n"
            f"Results: {r.results_path or 'N/A'}\n"
            f"Reports: {len(r.reports)} generated",
            title="Job Result",
            border_style=status_color,
        ))

        for rep in r.reports:
            console.print(f"  [dim]• {rep}[/dim]")

        if r.error:
            console.print(f"[red]Error: {r.error}[/red]")
