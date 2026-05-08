"""AI scan planning agent for iStrix."""

from rich.console import Console
from rich.panel import Panel

from istrix.ai.client import get_llm
from istrix.engine.tiers import list_tiers

console = Console()

PLANNER_SYSTEM_PROMPT = """You are an expert penetration tester and security consultant. 
Your job is to help plan network reconnaissance and vulnerability scanning operations.

Given a target (IP address, hostname, or network range), suggest:
1. The best scan tier (quick/normal/full/aggressive/stealth) and why
2. Any special considerations (stealth requirements, scope limitations, etc.)
3. What follow-up actions to take after initial results
4. Any risks or precautions to be aware of

Available scan tiers:
{tiers_description}

Keep your response focused on the target provided. Be concise and actionable.
"""


def create_scan_plan(target: str) -> Panel:
    """Create an AI-generated scan plan for a target.

    Args:
        target: Target IP, hostname, or CIDR.

    Returns:
        A Rich Panel with the scan plan.
    """
    tiers = list_tiers()
    tiers_desc = "\n".join(
        f"- **{t.name}** ({t.label}): {t.description}"
        for t in tiers
    )

    system_prompt = PLANNER_SYSTEM_PROMPT.format(tiers_description=tiers_desc)

    try:
        llm = get_llm()
        response = llm.chat([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Target to scan: {target}"},
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

    return Panel(
        response,
        title=f"[bold cyan]Scan Plan for {target}[/bold cyan]",
        border_style="cyan",
    )


def suggest_tier(target: str) -> str:
    """Quick AI suggestion for which scan tier to use.

    Returns:
        Tier name string, or 'normal' as fallback.
    """
    tiers = list_tiers()
    tiers_desc = "\n".join(
        f"- {t.name}: {t.description}"
        for t in tiers
    )

    prompt = f"""Given this target: {target}

Available scan tiers:
{tiers_desc}

Suggest the single best tier as just the tier name (one word: quick, normal, full, aggressive, or stealth).
Reply with ONLY the tier name, nothing else."""

    try:
        llm = get_llm()
        response = llm.chat([
            {"role": "user", "content": prompt},
        ])
        tier_name = response.strip().lower()
        valid_tiers = {t.name for t in tiers}
        if tier_name in valid_tiers:
            return tier_name
        return "normal"
    except Exception:
        return "normal"
