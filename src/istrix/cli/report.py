"""istrix report command — generate professional pentest reports."""

from pathlib import Path

import typer
from rich.console import Console

from istrix.models.risk import RiskProfile
from istrix.reporting.generator import generate_report, generate_report_index, generate_per_host_reports

console = Console()


def _build_subnet_map(findings: list[dict]) -> dict[str, str]:
    """Auto-build subnet_map from host IPs in findings, grouped by /24 prefix."""
    subnet_map: dict[str, str] = {}
    seen = set()
    for f in findings:
        host = f.get("host", "")
        if not host or host in ("0.0.0.0", "127.0.0.1"):
            continue
        parts = host.split(".")
        if len(parts) != 4:
            continue
        sn = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        if sn not in seen:
            seen.add(sn)
            subnet_map[sn] = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
    return subnet_map


def _results_basename(path: Path) -> str:
    """Derive report group name from results file: results_customer.json → customer."""
    name = path.stem  # results_customer
    if name.startswith("results_"):
        name = name[len("results_"):]
    elif name.startswith("result_"):
        name = name[len("result_"):]
    return name or "scan"


def report_command(
    results_files: list[Path] = typer.Argument(..., help="One or more JSON results files from istrix scan"),
    level: str = typer.Option("detail", "--level", "-l",
        help="Report level: brief, detail, threat, remediation"),
    output_format: str = typer.Option("html", "--format", "-f",
        help="Output format: html, pdf, md"),
    output_dir: Path = typer.Option("./private/reports", "--output-dir", "-o",
        help="Output directory for reports"),
    customer: str = typer.Option("", "--customer", "-c",
        help="Customer name for report header"),
    site: str = typer.Option("", "--site", "-s",
        help="Site name for report header"),
    notes: str = typer.Option("", "--notes", "-n",
        help="Scan notes to include in report"),
    all_levels: bool = typer.Option(False, "--all", "-a",
        help="Generate all report levels (brief, detail, threat, remediation)"),
    all_formats: bool = typer.Option(False, "--all-formats",
        help="Generate HTML + PDF + MD for the selected level(s)"),
    parallel: int = typer.Option(0, "--parallel", "-p",
        help="Parallel workers for per-host report generation (0: sequential, PDF capped at 4 due to weasyprint)"),
    # --- Risk Assessment Criteria ---
    public: bool = typer.Option(False, "--public", help="Target is publicly reachable on the internet"),
    scan_origin: str = typer.Option("private_lan", "--scan-origin",
        help="Scan origin: private_lan, public_wan, extranet_vpn"),
    financial_data: str = typer.Option("N", "--financial-data",
        help="Financial data: N, Y-encrypted, Y-unencrypted"),
    privacy_data: str = typer.Option("N", "--privacy-data",
        help="PII/Privacy data: N, Y-encrypted, Y-unencrypted"),
    healthcare_data: str = typer.Option("N", "--healthcare-data",
        help="Healthcare/PHI data: N, Y-encrypted, Y-unencrypted"),
    government_data: str = typer.Option("N", "--government-data",
        help="Government data: N, CUI, ITAR, Classified, FOUO"),
    business_data: str = typer.Option("N", "--business-data",
        help="Sensitive business data: N, Y-encrypted, Y-unencrypted"),
    mfa: bool = typer.Option(False, "--mfa", help="Multi-factor authentication is enforced"),
    patch_age: str = typer.Option("unknown", "--patch-age",
        help="Patch status: recent, stale, critical, unknown"),
    exploit_public: bool = typer.Option(False, "--exploit-public",
        help="Public exploits/PoCs known for discovered CVEs"),
    mgmt_exposed: bool = typer.Option(False, "--mgmt-exposed",
        help="Management interfaces exposed to scan origin"),
    compliance: str = typer.Option("none", "--compliance",
        help="Compliance framework: none, pci_dss, hipaa, soc2, iso27001, nist_800-53"),
    per_host: bool = typer.Option(False, "--per-host",
        help="Split multi-host results into per-host reports in subdirectories"),
):
    """Generate a professional penetration test report.

    Pass multiple JSON files for an aggregated multi-host report.
    A single file generates a per-host report.

    Examples:
        istrix report results.json --level brief
        istrix report host_a.json host_b.json --level detail --all-formats
        istrix report *.json --all --all-formats -c "ACME Corp" --public --compliance pci_dss
    """
    missing = [f for f in results_files if not f.exists()]
    if missing:
        console.print(f"[red]Files not found:[/red] {', '.join(str(m) for m in missing)}")
        raise typer.Exit(code=1)

    risk = RiskProfile(
        public_reachable=public,
        scan_origin=scan_origin,
        financial_data=financial_data,
        privacy_data=privacy_data,
        healthcare_data=healthcare_data,
        government_data=government_data,
        business_sensitive=business_data,
        mfa_enforced=mfa,
        patch_age=patch_age,
        exploit_public=exploit_public,
        mgmt_exposed=mgmt_exposed,
        compliance_framework=compliance,
    )

    levels = ["brief", "detail", "threat", "remediation"] if all_levels else [level]
    formats = ["html", "pdf", "md"] if all_formats else [output_format]
    generated: list = []

    if per_host:
        for rf in results_files:
            # Group output under reports/<basename>/ (e.g., reports/customer/)
            base_name = _results_basename(rf)
            per_host_dir = output_dir / base_name

            # Auto-build subnet_map from host IPs for subnet-grouped organization
            import json as _json
            subnet_map: dict[str, str] = {}
            try:
                with open(rf) as f:
                    data = _json.load(f)
                subnet_map = _build_subnet_map(data.get("findings", []))
            except Exception:
                pass

            paths = generate_per_host_reports(
                results_path=str(rf),
                levels=levels,
                formats=formats,
                output_dir=str(per_host_dir),
                customer_name=customer,
                site_name=site,
                scan_notes=notes,
                risk_profile=risk,
                max_workers=parallel if parallel > 0 else None,
                subnet_map=subnet_map if subnet_map else None,
            )
            generated.extend(paths)
    else:
        for lvl in levels:
            for fmt in formats:
                try:
                    path = generate_report(
                        results_paths=[str(f) for f in results_files],
                        level=lvl,
                        output_format=fmt,
                        output_dir=str(output_dir),
                        customer_name=customer,
                        site_name=site,
                        scan_notes=notes,
                        risk_profile=risk,
                    )
                    generated.append(path)
                    console.print(f"[green]Generated:[/green] {path}")
                except ImportError as e:
                    console.print(f"[red]{e}[/red]")
                    raise typer.Exit(code=1)
                except Exception as e:
                    console.print(f"[red]Error generating {lvl}/{fmt}:[/red] {e}")

    tag = "per-host" if per_host else ("aggregate" if len(results_files) > 1 else "per-host")
    # Determine the actual output directory for display and index
    target_dir = output_dir
    if per_host and results_files:
        target_dir = output_dir / _results_basename(results_files[0])
    console.print()
    console.print(f"[bold green]{len(generated)} report(s) generated[/bold green] ({tag}) in {target_dir.absolute()}")

    # Generate index page at the output level
    # (per_host mode: generate_per_host_reports already produces a detailed index)
    if not per_host:
        try:
            idx = generate_report_index(
                output_dir=str(target_dir),
                customer_name=customer,
                site_name=site,
            )
            console.print(f"[green]Index:[/green] {idx}")
        except Exception as e:
            console.print(f"[yellow]Index skipped:[/yellow] {e}")
