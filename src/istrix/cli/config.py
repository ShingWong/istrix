"""istrix config command — configure tools and settings."""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from istrix.utils.deps import check_tools

console = Console()

config_app = typer.Typer(help="Configure iStrix settings and view tool status", no_args_is_help=True)


@config_app.command()
def status():
    """Show tool availability and configuration status."""
    tools = check_tools()

    console.print()
    console.print(Panel.fit(
        "[bold]iStrix Configuration Status[/bold]",
        border_style="cyan",
    ))

    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool", style="cyan")
    table.add_column("Required", width=10)
    table.add_column("Status", width=20)
    table.add_column("Path")

    for tool in tools:
        status_text = "[green]Available[/green]" if tool.available else "[red]Not Found[/red]"
        req_text = "[red]Required[/red]" if tool.required else "[dim]Optional[/dim]"
        path_text = tool.path or "-"

        table.add_row(tool.name, req_text, status_text, path_text)

    console.print(table)
    console.print()
    console.print("[dim]Install missing tools with your system package manager.[/dim]")
    console.print("[dim]Required tools must be present for scanning to work.[/dim]")
    console.print()


@config_app.command()
def init():
    """Initialize iStrix configuration (interactive setup)."""
    from pathlib import Path

    console.print()
    console.print("[bold cyan]iStrix Setup[/bold cyan]")
    console.print()

    console.print("Module directories:")
    console.print(f"  Config: [dim]{Path(__file__).parent.parent.parent.parent / 'config'}[/dim]")
    console.print()

    tools = check_tools()
    missing_required = [t for t in tools if t.required and not t.available]
    if missing_required:
        console.print("[red]Missing required tools:[/red]")
        for t in missing_required:
            console.print(f"  • {t.name}")
        console.print()
        console.print("[yellow]Please install required tools before running scans.[/yellow]")
    else:
        console.print("[green]All required tools are available.[/green]")

    missing_optional = [t for t in tools if not t.required and not t.available]
    if missing_optional:
        console.print()
        console.print("[dim]Optional tools not found (some features limited):[/dim]")
        for t in missing_optional:
            console.print(f"  [dim]• {t.name}[/dim]")

    console.print()
    console.print("[dim]Edit config files in the config/ directory to customize tiers and AI settings.[/dim]")
    console.print()
