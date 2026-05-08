"""Real-time CVE enrichment using NVD API via nvdlib.

Enriches nmap service and vulnerability findings with live CVE data from the
National Vulnerability Database.  Requires ``nvdlib`` (already declared as
the ``[cve]`` optional dependency).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from istrix.engine.modules.base import ScanModule
from istrix.models.finding import Finding


class CVEEnrichModule(ScanModule):
    """Enrich service/vulnerability findings with live CVE data from NVD."""

    name = "cve_enrich"
    description = "Query NVD for CVEs matching detected services and versions"
    consumed_types = ["service", "vulnerability"]
    produced_types = ["vulnerability"]
    optional = True

    _MIN_CVSS = 7.0
    _DELAY_SECONDS = 6.0
    _MAX_CVES_PER_SERVICE = 10

    def run(self, findings: list[Finding]) -> list[Finding]:
        results: list[Finding] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            import nvdlib  # type: ignore[import-untyped]
        except ImportError:
            return results

        service_findings = [f for f in findings if f.type == "service" and f.evidence]
        vuln_findings = [f for f in findings if f.type == "vulnerability" and f.cve]
        seen_cves: set[str] = set()
        enriched_cves: set[str] = set()
        seen_combos: set[tuple[str, str]] = set()

        for f in service_findings:
            product, version = self._parse_evidence(f.evidence or "")
            if not product:
                continue
            combo = (product, version)
            if combo in seen_combos:
                continue
            seen_combos.add(combo)

            cves = self._search_cves_for_service(nvdlib, product, version)
            time.sleep(self._DELAY_SECONDS)

            for cve_data in cves:
                cve_id = cve_data.get("id", "")
                if not cve_id or cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                severity = self._classify_cvss(cve_data.get("cvss", 0))
                results.append(Finding(
                    type="vulnerability",
                    host=f.host,
                    port=f.port,
                    protocol=f.protocol,
                    detail=f"{cve_id}: {cve_data.get('title', '')[:180]}",
                    severity=severity,
                    source="cve_enrich",
                    cve=cve_id,
                    evidence=cve_data.get("description", "")[:800],
                    timestamp=timestamp,
                ))

        for f in vuln_findings:
            if not f.cve or f.cve in enriched_cves:
                continue
            enriched_cves.add(f.cve)
            enriched = self._enrich_cve(nvdlib, f.cve)
            time.sleep(self._DELAY_SECONDS)
            if enriched:
                if enriched.get("cvss"):
                    new_sev = self._classify_cvss(enriched["cvss"])
                    if self._severity_rank(new_sev) > self._severity_rank(f.severity):
                        f.severity = new_sev
                if enriched.get("title") and len(f.detail) < 100:
                    f.detail = f"{f.cve}: {enriched['title'][:180]}"
                if enriched.get("description") and not f.evidence:
                    f.evidence = enriched["description"][:800]

        return results

    def _parse_evidence(self, evidence: str) -> tuple[str, str]:
        """Extract product and version from nmap evidence string.

        Handles formats like 'product=OpenSSH version=7.6p1 extrainfo=...'
        """
        product = ""
        version = ""
        for part in evidence.split():
            if "=" in part:
                key, _, val = part.partition("=")
                key = key.strip().lower()
                val = val.strip()
                if key == "product" and val:
                    product = val
                elif key == "version" and val:
                    version = val
        return product, version

    def _search_cves_for_service(self, nvdlib, product: str, version: str) -> list[dict]:
        """Search NVD for CVEs matching a service product/version."""
        keyword = product

        try:
            results = nvdlib.searchCVE(
                keywordSearch=keyword,
                limit=50,
            )
        except Exception:
            return []

        cves: list[dict] = []
        for cve in results or []:
            cve_id = getattr(cve, "id", None)
            if not cve_id:
                continue

            cvss_score = self._get_cvss(cve)
            if cvss_score < self._MIN_CVSS:
                continue

            description = ""
            desc_list = getattr(cve, "descriptions", None) or []
            for d in desc_list:
                if getattr(d, "lang", "") == "en":
                    description = getattr(d, "value", "")
                    break

            cves.append({
                "id": cve_id,
                "title": description[:120] if description else cve_id,
                "cvss": cvss_score,
                "description": description,
            })

        return cves

    def _enrich_cve(self, nvdlib, cve_id: str) -> dict | None:
        """Fetch enriched metadata for a single known CVE."""
        try:
            results = nvdlib.searchCVE(cveId=cve_id)
        except Exception:
            return None

        for cve in (results or []):
            cid = getattr(cve, "id", None)
            if cid != cve_id:
                continue

            cvss_score = self._get_cvss(cve)

            description = ""
            desc_list = getattr(cve, "descriptions", None) or []
            for d in desc_list:
                if getattr(d, "lang", "") == "en":
                    description = getattr(d, "value", "")
                    break

            return {
                "id": cve_id,
                "title": description[:120] if description else cve_id,
                "cvss": cvss_score,
                "description": description,
            }

        return None

    @staticmethod
    def _get_cvss(cve) -> float:
        """Extract CVSS score from an nvdlib CVE object, trying v3.1 > v3.0 > v2."""
        for attr in ("v31score", "v30score", "v2score"):
            try:
                val = getattr(cve, attr, None)
                if val is None:
                    continue
                if isinstance(val, (list, tuple)):
                    if len(val) > 0 and val[0] is not None:
                        return float(val[0])
                elif isinstance(val, (int, float)):
                    return float(val)
            except (TypeError, ValueError, AttributeError, KeyError):
                continue
        return 0.0

    @staticmethod
    def _classify_cvss(score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    @staticmethod
    def _severity_rank(sev: str) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 0)
