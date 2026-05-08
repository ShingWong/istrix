"""istrix AI commands — plan and consult."""

import typer
from rich.console import Console

console = Console()


def plan_command(
    target: str = typer.Argument(..., help="Target to plan a scan for"),
):
    """Generate an AI-assisted scan plan for a target.

    The AI analyzes the target and suggests the best scan tier and approach.

    Requires: pip install istrix[ai] and a configured AI provider.
    Set STRIX_AI_PROVIDER, STRIX_AI_API_KEY, STRIX_AI_MODEL environment variables.

    Examples:
        istrix plan example.com
        istrix plan 10.0.0.0/24
    """
    try:
        from istrix.ai.planner import create_scan_plan
    except ImportError:
        console.print(
            "[red]AI features not installed.[/red] "
            "Run: pip install istrix[ai]"
        )
        raise typer.Exit(code=1)

    plan = create_scan_plan(target)
    console.print(plan)


def consult_command(
    results_file: str = typer.Argument(..., help="Path to a JSON results file from istrix scan"),
):
    """Analyze scan results with AI and suggest next steps.

    The AI reviews findings, correlates vulnerabilities, and suggests
    follow-up scans or exploitation paths.

    Requires: pip install istrix[ai] and a configured AI provider.
    Set STRIX_AI_PROVIDER, STRIX_AI_API_KEY, STRIX_AI_MODEL environment variables.

    Examples:
        istrix consult results_aggressive.json
    """
    try:
        from istrix.ai.consultant import analyze_results
    except ImportError:
        console.print(
            "[red]AI features not installed.[/red] "
            "Run: pip install istrix[ai]"
        )
        raise typer.Exit(code=1)

    analysis = analyze_results(results_file)
    console.print(analysis)
