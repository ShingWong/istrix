#!/usr/bin/env python3
"""Sync the iStrix vulnerability knowledge base from NVD.

Fetches CVEs with CVSS >= 7.0 published within the lookback window (default
90 days) via the nvdlib library and merges them into ``config/vulndb.yaml``.

Manual entries in the YAML (``source: manual``) are preserved; auto-fetched
entries are updated or added.  Exit code 0 means no changes were needed;
exit code 1 means the file was modified and should be committed.

Auto-generated commands use:
  - Fix version extraction from description (e.g. "before 9.8" → 9.8)
  - Product detection to generate OS-aware upgrade commands
  - Fallback generic advice when product is unknown
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VULNDB_PATH = PROJECT_ROOT / "config" / "vulndb.yaml"

NVD_API_KEY_ENV = "NVD_API_KEY"

# ── Product → regex + generic commands ─────────────────────────────

_PRODUCT_PATTERNS = [
    (r"openssh", "OpenSSH", [
        "apt update && apt install --only-upgrade openssh-server openssh-client -y",
        "sshd -t && systemctl restart sshd",
    ]),
    (r"nginx", "nginx", [
        "apt update && apt install --only-upgrade nginx -y",
        "nginx -t && systemctl restart nginx",
    ]),
    (r"apache|httpd", "Apache/httpd", [
        "apt update && apt install --only-upgrade apache2 -y",
        "systemctl restart apache2",
    ]),
    (r"bind|named", "BIND", [
        "apt update && apt install --only-upgrade bind9 -y",
        "rndc reload",
    ]),
    (r"mysql|mariadb", "MySQL/MariaDB", [
        "apt update && apt install --only-upgrade mysql-server -y",
        "systemctl restart mysql",
    ]),
    (r"postgresql|postgres", "PostgreSQL", [
        "apt update && apt install --only-upgrade postgresql -y",
        "systemctl restart postgresql",
    ]),
    (r"linux kernel|kernel", "Linux Kernel", [
        "apt update && apt upgrade -y && reboot",
    ]),
    (r"kubernetes|kubelet|kubectl", "Kubernetes", [
        "apt update && apt install --only-upgrade kubelet kubeadm kubectl -y",
        "systemctl restart kubelet",
    ]),
    (r"docker|moby|containerd|runc", "Docker/containerd", [
        "apt update && apt install --only-upgrade docker-ce containerd.io -y",
        "systemctl restart docker",
    ]),
    (r"curl|libcurl", "curl", [
        "apt update && apt install --only-upgrade curl libcurl4 -y",
    ]),
    (r"glibc|gnu c library", "glibc", [
        "apt update && apt install --only-upgrade libc6 -y && reboot",
    ]),
    (r"openssl", "OpenSSL", [
        "apt update && apt install --only-upgrade openssl libssl-dev -y",
    ]),
    (r"gsoap|soap", "gSOAP", [
        "Download latest gSOAP from https://www.genivia.com/downloads.html",
        "Recompile applications linked against gSOAP",
    ]),
    (r"exim|exim4", "Exim", [
        "apt update && apt install --only-upgrade exim4 -y",
        "systemctl restart exim4",
    ]),
    (r"php", "PHP", [
        "apt update && apt install --only-upgrade php -y",
        "systemctl restart php-fpm",
    ]),
]

_FIX_PATTERNS = [
    r"fixed\s+in\s+(?:version\s+)?(\d+(?:\.\d+)+[a-z]?\d*)",
    r"prior\s+to\s+(?:version\s+)?(\d+(?:\.\d+)+[a-z]?\d*)",
    r"before\s+(?:version\s+)?(\d+(?:\.\d+)+[a-z]?\d*)",
    r"(?:before|prior\s+to|earlier\s+than)\s+(\d+(?:\.\d+)+[a-z]?\d*)",
]


def _extract_fixed_version(description: str) -> str:
    """Extract fixed version from CVE description text."""
    for pattern in _FIX_PATTERNS:
        m = re.search(pattern, description, re.IGNORECASE)
        if m:
            v = m.group(1).rstrip(".,;):")
            if re.match(r"\d+(?:\.\d+)+", v):
                return v
    return ""


def _generate_commands(description: str, fixed_version: str = "") -> list[str]:
    """Generate basic remediation commands from CVE description."""
    desc_lower = description.lower()
    cmds: list[str] = []

    for pattern, product_name, default_cmds in _PRODUCT_PATTERNS:
        if re.search(pattern, desc_lower, re.IGNORECASE):
            if fixed_version:
                cmds.append(f"Upgrade {product_name} to version >= {fixed_version}")
            cmds.extend(default_cmds)
            return cmds

    # Generic fallback with fix version if available
    if fixed_version:
        cmds.append(f"Upgrade affected software to version >= {fixed_version}")
        cmds.append("Check vendor advisory for specific update instructions")
    else:
        cmds.append("Apply vendor security patches")
        cmds.append("Check NVD for specific remediation guidance")
    return cmds


def load_vulndb(path: Path) -> dict:
    """Load the existing vulndb YAML, returning full document."""
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    return {"metadata": {}, "vulnerabilities": {}, "fallback": {}}


def save_vulndb(path: Path, data: dict) -> None:
    """Write the vulndb back to YAML."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True,
                       sort_keys=False, width=120)


def fetch_nvd_cves(lookback_days: int = 90, min_cvss: float = 7.0) -> dict[str, dict]:
    """Fetch CVEs from NVD matching criteria. Returns {CVE-ID: entry-dict}."""
    try:
        import nvdlib  # type: ignore[import-untyped]
    except ImportError:
        print("[sync_vulndb] nvdlib not installed; skipping NVD fetch.", file=sys.stderr)
        return {}

    api_key = os.environ.get(NVD_API_KEY_ENV)
    pub_start = (datetime.utcnow() - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
    pub_end = datetime.utcnow().strftime("%Y-%m-%d")

    results: dict[str, dict] = {}

    try:
        kwargs = {"pubStartDate": pub_start, "pubEndDate": pub_end, "delay": 6}
        if api_key:
            kwargs["key"] = api_key
            kwargs["delay"] = 2

        response = nvdlib.searchCVE(**kwargs)  # type: ignore[arg-type]

        for cve in response:
            cve_id = getattr(cve, "id", None)
            if not cve_id:
                continue

            cvss_score = 0.0
            cvss_vector = ""

            # Try CVSS v3.1 first, fall back to v3.0, v2.0
            metrics = getattr(cve, "v31score", None) or [None]
            if metrics and metrics[0] is not None:
                cvss_score = float(metrics[0])
                vectors = getattr(cve, "v31vector", None)
                cvss_vector = str(vectors[0]) if vectors else ""
            else:
                metrics = getattr(cve, "v30score", None) or [None]
                if metrics and metrics[0] is not None:
                    cvss_score = float(metrics[0])
                    vectors = getattr(cve, "v30vector", None)
                    cvss_vector = str(vectors[0]) if vectors else ""
                else:
                    metrics = getattr(cve, "v2score", None) or [None]
                    if metrics and metrics[0] is not None:
                        cvss_score = float(metrics[0])

            if cvss_score < min_cvss:
                continue

            description = getattr(cve, "descriptions", None)
            summary = ""
            if description:
                for d in description:
                    if getattr(d, "lang", "") == "en":
                        summary = getattr(d, "value", "")
                        break

            results[cve_id] = {
                "title": summary[:120] if summary else cve_id,
                "cvss": str(cvss_score),
                "vector": cvss_vector,
                "summary": summary,
                "exploit_narrative": (
                    f"This vulnerability (CVSS {cvss_score}) was automatically imported from NVD. "
                    "It affects services that may be present on the target. Refer to the NVD link "
                    "for exploitation details and proof-of-concept availability."
                ),
                "commands": _generate_commands(summary, _extract_fixed_version(summary)),
                "source": "nvd-auto",
                "last_fetched": datetime.utcnow().strftime("%Y-%m-%d"),
            }

    except Exception as exc:
        print(f"[sync_vulndb] NVD fetch error: {exc}", file=sys.stderr)
        return {}

    print(f"[sync_vulndb] Fetched {len(results)} CVEs with CVSS >= {min_cvss}", file=sys.stderr)
    return results


def merge_cves(existing: dict, fetched: dict) -> tuple[dict, bool]:
    """Merge fetched CVEs into existing, preserving manual entries. Returns (merged, changed)."""
    vulns = dict(existing.get("vulnerabilities", {}))
    changed = False

    for cve_id, entry in fetched.items():
        existing_entry = vulns.get(cve_id)
        if existing_entry and existing_entry.get("source") == "manual":
            continue
        if existing_entry == entry:
            continue
        vulns[cve_id] = entry
        changed = True

    existing["vulnerabilities"] = vulns
    return existing, changed


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync iStrix vulnerability DB from NVD")
    parser.add_argument("--lookback", type=int, default=90,
                        help="Days to look back for new CVEs (default: 90)")
    parser.add_argument("--min-cvss", type=float, default=7.0,
                        help="Minimum CVSS score (default: 7.0)")
    parser.add_argument("--check-only", action="store_true",
                        help="Exit 1 if an update is available but do not write")
    args = parser.parse_args()

    existing = load_vulndb(VULNDB_PATH)
    fetched = fetch_nvd_cves(lookback_days=args.lookback, min_cvss=args.min_cvss)

    merged, changed = merge_cves(existing, fetched)

    merged.setdefault("metadata", {})
    merged["metadata"]["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d")
    merged["metadata"]["cve_count"] = len(merged.get("vulnerabilities", {}))

    if not changed:
        print("[sync_vulndb] No changes needed.")
        return 0

    if args.check_only:
        print(f"[sync_vulndb] Changes available ({len(fetched)} new/updated CVEs) but --check-only set.")
        return 1

    save_vulndb(VULNDB_PATH, merged)
    print(f"[sync_vulndb] Written {VULNDB_PATH} ({merged['metadata']['cve_count']} CVEs).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
