#!/usr/bin/env python3
"""Regenerate remediation reports with version-specific patch info."""
import json
import multiprocessing
import sys
import time
import os
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "src"))
os.chdir(Path(__file__).parent)

from istrix.reporting.generator import generate_report, generate_report_index, _ip_sort_key  # noqa: E402

def process_host(args):
    host_ip, host_dir_str, customer, site, results_path = args
    host_dir = Path(host_dir_str)
    host_json = host_dir / f"{host_ip}.json"
    if not host_json.exists():
        return host_ip
    
    for old in list(host_dir.glob("istrix_report_remediation_*")):
        old.unlink()
    
    for level in ["remediation"]:
        for fmt in ["html", "md"]:
            try:
                generate_report(
                    results_paths=[str(host_json)],
                    level=level, output_format=fmt,
                    output_dir=str(host_dir),
                    customer_name=customer, site_name=site,
                )
            except Exception:
                pass
    return host_ip

def regenerate(dirname, results_path, customer, site, workers=30):
    base = Path(dirname)
    with open(results_path) as f:
        data = json.load(f)
    
    hosts = {}
    for fd in data['findings']:
        hosts.setdefault(fd['host'], []).append(fd)
    host_list = sorted(hosts, key=_ip_sort_key)
    
    print(f"\n{dirname}: {len(host_list)} hosts, {workers} workers")
    start = time.monotonic()
    
    tasks = [(h, str(base / h), customer, site, results_path) for h in host_list]
    
    with multiprocessing.Pool(workers) as pool:
        for i, _ in enumerate(pool.imap_unordered(process_host, tasks)):
            if (i + 1) % 20 == 0:
                print(f"  {i+1}/{len(host_list)} ({(time.monotonic()-start):.0f}s)")
    
    elapsed = time.monotonic() - start
    print(f"  HTML+MD done in {elapsed:.0f}s")
    
    # PDFs — separate pass with 4 workers (weasyprint bottleneck)
    print("  PDF phase (4 workers)...")
    pdf_start = time.monotonic()
    with multiprocessing.Pool(4) as pool:
        for _ in pool.imap_unordered(process_host_pdf, tasks):
            pass
    print(f"  PDF done in {(time.monotonic()-pdf_start):.0f}s")
    
    # Regenerate per-host indexes
    for d in base.iterdir():
        if d.is_dir() and "." in d.name:
            generate_report_index(str(d), customer_name=customer, site_name=f"{site}/{d.name}")
    
    # Aggregate remediation
    generate_report(
        results_paths=[results_path], level="remediation", output_format="html",
        output_dir=str(base), customer_name=customer, site_name=site,
    )
    generate_report(
        results_paths=[results_path], level="remediation", output_format="md",
        output_dir=str(base), customer_name=customer, site_name=site,
    )
    generate_report_index(str(base), customer_name=customer, site_name=site)
    print("  Indexes + aggregate regenerated")
    return elapsed

def process_host_pdf(args):
    host_ip, host_dir_str, customer, site, results_path = args
    host_dir = Path(host_dir_str)
    host_json = host_dir / f"{host_ip}.json"
    if not host_json.exists():
        return host_ip
    try:
        generate_report(
            results_paths=[str(host_json)],
            level="remediation", output_format="pdf",
            output_dir=str(host_dir),
            customer_name=customer, site_name=site,
        )
    except Exception:
        pass
    return host_ip

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Regenerate remediation reports")
    parser.add_argument("results", nargs="+", help="Scan result JSON files")
    parser.add_argument("-o", "--output", default="private/reports", help="Output directory (default: private/reports)")
    parser.add_argument("-c", "--customer", default="Customer", help="Customer name")
    parser.add_argument("-s", "--site", default="Site", help="Site name")
    args = parser.parse_args()

    for rpath in args.results:
        regenerate(args.output, rpath, args.customer, args.site)
    print("\nAll remediation reports updated with version-specific patch info")
