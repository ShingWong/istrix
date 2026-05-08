"""Rich-based terminal output for iStrix."""

from contextlib import contextmanager

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from istrix.models.finding import Finding

console = Console()


def display_findings(findings: list[Finding], format: str = "table"):
    """Display findings in the terminal.

    Args:
        findings: List of findings to display.
        format: 'table' or 'list'.
    """
    if format == "list":
        for f in findings:
            color = _sev_color(f.severity)
            console.print(
                f"[{color}]{f.severity:8}[/{color}] "
                f"[dim]{f.host:18}[/dim] "
                f"{f.port or '-':>5} "
                f"{f.detail[:80]}"
            )
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Host", style="dim", width=18)
        table.add_column("Port", width=7, justify="right")
        table.add_column("Type", width=14)
        table.add_column("Detail", width=50)
        table.add_column("Severity", width=10)

        for f in findings:
            table.add_row(
                f.host[:17],
                str(f.port) if f.port is not None else "-",
                f.type,
                f.detail[:49],
                f"[{_sev_color(f.severity)}]{f.severity}[/{_sev_color(f.severity)}]",
            )

        console.print(table)


def display_summary(findings: list[Finding]):
    """Display a brief summary of findings."""
    hosts: set[str] = set()
    ports: set[str] = set()
    sev_counts: dict[str, int] = {}

    for f in findings:
        hosts.add(f.host)
        if f.port is not None:
            ports.add(f"{f.host}:{f.port}")
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    console.print(f"  [bold]{len(hosts)}[/bold] hosts scanned")
    console.print(f"  [bold]{len(ports)}[/bold] open ports found")
    console.print(f"  [bold]{len(findings)}[/bold] total findings")
    for sev, count in sorted(sev_counts.items(),
                             key=lambda x: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(x[0], 0),
                             reverse=True):
        console.print(f"  [{_sev_color(sev)}]{sev}: {count}[/{_sev_color(sev)}]")


@contextmanager
def live_progress(message: str = "Scanning"):
    """Context manager that shows a spinner with a message."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task(f"[cyan]{message}...[/cyan]", total=None)
        yield
        progress.remove_task(task)


def _sev_color(severity: str) -> str:
    colors = {
        "critical": "red",
        "high": "bright_red",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }
    return colors.get(severity, "white")
