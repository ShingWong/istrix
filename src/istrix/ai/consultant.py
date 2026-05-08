"""AI result consultation agent for iStrix."""


from rich.console import Console
from rich.panel import Panel

from istrix.ai.client import get_llm
from istrix.reporting.json_export import load_from_json

console = Console()

CONSULTANT_SYSTEM_PROMPT = """You are an expert penetration tester analyzing scan results.
Your job is to:

1. Summarize the key findings in 1-2 sentences
2. Highlight the most critical issues found (severity critical/high)
3. Identify interesting services that deserve further investigation
4. Suggest 2-3 concrete follow-up scans or manual tests
5. Note any patterns, correlations, or suspicious configurations

Be specific and actionable. Reference actual host IPs, ports, and services from the findings.
If CVE IDs are present, mention them.
"""


def analyze_results(results_file: str) -> Panel:
    """Analyze scan results with AI and provide recommendations.

    Args:
        results_file: Path to a JSON results file from istrix scan -o.

    Returns:
        A Rich Panel with analysis and recommendations.
    """
    try:
        result = load_from_json(results_file)
    except FileNotFoundError:
        return Panel(
            f"[red]Results file not found:[/red] {results_file}",
            title="[red]Error[/red]",
            border_style="red",
        )
    except Exception as e:
        return Panel(
            f"[red]Failed to load results:[/red] {e}",
            title="[red]Error[/red]",
            border_style="red",
        )

    summary = result.summary()
    findings = result.findings

    findings_preview = _format_findings(findings[:50])

    user_message = f"""Scan Summary:
- Hosts scanned: {summary['hosts_scanned']}
- Open ports: {summary['ports_open']}
- Total findings: {summary['total_findings']}
- By severity: {summary.get('by_severity', {})}

Key Findings (first 50):
{findings_preview}

Please analyze these results and provide recommendations."""

    try:
        llm = get_llm()
        response = llm.chat([
            {"role": "system", "content": CONSULTANT_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ])
    except RuntimeError as e:
        return Panel(
            f"[red]AI not configured:[/red] {e}\n\n"
            "Set STRIX_AI_API_KEY or run: [cyan]istrix config init[/cyan]",
            title="[red]AI Error[/red]",
            border_style="red",
        )
    except ImportError as e:
        return Panel(
            f"[red]Missing dependencies:[/red] {e}",
            title="[red]AI Error[/red]",
            border_style="red",
        )

    summary_text = (
        f"[bold]Hosts:[/bold] {summary['hosts_scanned']}  "
        f"[bold]Ports:[/bold] {summary['ports_open']}  "
        f"[bold]Findings:[/bold] {summary['total_findings']}\n\n"
        f"{response}"
    )

    return Panel(
        summary_text,
        title="[bold cyan]Result Analysis[/bold cyan]",
        border_style="cyan",
    )


def _format_findings(findings: list) -> str:
    """Format findings as a compact text representation."""
    lines = []
    for f in findings:
        host = f.host if hasattr(f, 'host') else f.get('host', '?')
        port = f.port if hasattr(f, 'port') else f.get('port', '-')
        detail = f.detail if hasattr(f, 'detail') else f.get('detail', '')
        sev = f.severity if hasattr(f, 'severity') else f.get('severity', 'info')
        cve = f.cve if hasattr(f, 'cve') else f.get('cve', '')

        line = f"[{sev}] {host}:{port} - {detail[:100]}"
        if cve:
            line += f" ({cve})"
        lines.append(line)

    return "\n".join(lines[:50])
