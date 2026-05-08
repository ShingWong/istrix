"""iStrix - AI-Powered Penetration Testing Orchestration Toolkit."""

import inspect
from typing import Any

import typer
from rich.console import Console
from typer.models import ArgumentInfo, OptionInfo

from istrix.cli.scan import scan_command
from istrix.cli.config import config_app
from istrix.cli.plan import plan_command, consult_command
from istrix.cli.report import report_command
from istrix.cli.job import job_app

console = Console()

app = typer.Typer(
    name="istrix",
    help="[bold cyan]iStrix[/bold cyan] — AI-powered penetration testing orchestration toolkit",
    rich_markup_mode="rich",
    invoke_without_command=True,
    no_args_is_help=True,
)


def _build_agent_help() -> str:
    """Generate agent-optimized help from live CLI function signatures.

    Introspects registered command functions to extract args, options,
    types, and defaults. This ensures --agent-help and --help never drift
    because both derive from the same source: the function signatures.
    """
    lines = ["# iStrix v0.1.0 — Agent Reference", ""]

    # Gather flat commands
    commands: list[tuple[str, Any, str]] = [
        ("scan", scan_command, scan_command.__doc__ or ""),
        ("plan", plan_command, plan_command.__doc__ or ""),
        ("consult", consult_command, consult_command.__doc__ or ""),
        ("report", report_command, report_command.__doc__ or ""),
    ]

    for cmd_name, cmd_func, doc in commands:
        lines.append(f"## istrix {cmd_name}")
        lines.append(doc.split("\n")[0].strip())
        lines.append("")

        sig = inspect.signature(cmd_func)
        args = []
        opts = []
        for name, param in sig.parameters.items():
            default = param.default
            typ = param.annotation if param.annotation is not inspect.Parameter.empty else "str"
            type_str = _format_type(typ)

            if isinstance(default, ArgumentInfo):
                args.append((name, type_str, getattr(default, "help", "") or "", default.default))
            elif isinstance(default, OptionInfo):
                decls = getattr(default, "param_decls", (f"--{name.replace('_', '-')}",))
                flags = ", ".join(decls) if decls else f"--{name}"
                help_text = getattr(default, "help", "") or ""
                val = getattr(default, "default", ...)
                opts.append((flags, type_str, help_text, val))

        if args:
            lines.append("Args:")
            for name, type_str, help_text, dv in args:
                req = "required" if dv is ... or dv is None else f"default: {_fmt_default(dv)}"
                help_suffix = f" — {help_text}" if help_text else ""
                lines.append(f"  {name:<18} {type_str:<12} ({req}){help_suffix}")
            lines.append("")

        if opts:
            lines.append("Options:")
            for flags, type_str, help_text, dv in opts:
                dv_str = _fmt_default(dv)
                help_suffix = f" — {help_text}" if help_text else ""
                lines.append(f"  {flags:<24} {type_str:<10} ({dv_str}){help_suffix}")
            lines.append("")

    # Config sub-app
    lines.append("## istrix config")
    for cmd in config_app.registered_commands:
        if cmd.callback is None:
            continue
        name = cmd.name or cmd.callback.__name__
        doc = (cmd.callback.__doc__ or "").strip().split("\n")[0]
        lines.append(f"  {name:<12} {doc}")
    lines.append("")

    # Job sub-app
    lines.append("## istrix job")
    for cmd in job_app.registered_commands:
        if cmd.callback is None:
            continue
        name = cmd.name or cmd.callback.__name__
        doc = (cmd.callback.__doc__ or "").strip().split("\n")[0]
        sig = inspect.signature(cmd.callback)
        params = []
        for pname, param in sig.parameters.items():
            if pname in ("ctx", "_ctx"):
                continue
            default = param.default
            if isinstance(default, ArgumentInfo):
                params.append(f"<{pname}>")
            elif isinstance(default, OptionInfo):
                decls = getattr(default, "param_decls", (f"--{pname.replace('_', '-')}",))
                params.append(decls[0] if decls else f"--{pname}")
        params_str = " ".join(params) if params else "(no args)"
        lines.append(f"  {name:<12} {params_str} — {doc}")
    lines.append("")

    lines.append("## Environment")
    lines.append("  STRIX_AI_PROVIDER    openai|anthropic|openrouter|ollama|lmstudio")
    lines.append("  STRIX_AI_API_KEY     provider API key")
    lines.append("  STRIX_AI_MODEL       model name")
    lines.append("  STRIX_AI_API_BASE    optional API base URL override")
    lines.append("")

    lines.append("## Dependencies")
    lines.append("  nmap     required, subprocess (non-root uses -sT fallback)")
    lines.append("  whatweb  optional, HTTP probe falls back to socket check")
    lines.append("  PDF:     pip install istrix[report]")
    lines.append("  AI:      pip install istrix[ai]")
    lines.append("")

    return "\n".join(lines)


def _format_type(typ: Any) -> str:
    """Format a Python type annotation for agent consumption."""
    raw = str(typ)
    raw = raw.replace("<class '", "").replace("'>", "")
    raw = raw.replace("typing.Optional[", "?").rstrip("]")
    raw = raw.replace("pathlib.", "").replace("Path", "path")
    if "list[" in raw:
        raw = raw.replace("list[", "").rstrip("]") + "..."
    return raw


def _fmt_default(dv: Any) -> str:
    """Format a default value for agent consumption."""
    if dv is ...:
        return "required"
    if dv == "":
        return '""'
    if dv is None:
        return "none"
    if isinstance(dv, bool):
        return str(dv).lower()
    return repr(dv).strip("'")


@app.callback(invoke_without_command=True)
def version_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit",
        is_eager=True,
    ),
    agent_help: bool = typer.Option(
        False,
        "--agent-help",
        help="Print concise agent-optimized reference (generated from signatures)",
        is_eager=True,
    ),
):
    if version:
        from istrix import __version__
        console.print(f"[bold]iStrix[/bold] v{__version__}")
        raise typer.Exit()
    if agent_help:
        console.print(_build_agent_help())
        raise typer.Exit()


# Top-level flat commands
app.command(name="scan")(scan_command)
app.command(name="plan")(plan_command)
app.command(name="consult")(consult_command)
app.command(name="report")(report_command)

# Subcommand groups
app.add_typer(config_app, name="config", help="Configure iStrix settings and tools")
app.add_typer(job_app, name="job", help="Manage scan jobs and pipelines")
