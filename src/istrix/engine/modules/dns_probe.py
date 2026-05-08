"""DNS probe module — hostname resolution, AD topology, and PTR sweeps.

Queries Active Directory DNS for:
  1. SRV records → DC locations, services, forest topology
  2. PTR reverse lookups → hostnames for every IP
  3. A forward lookups → cross-subnet DC resolution
"""

from __future__ import annotations

import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from istrix.engine.modules.base import ScanModule
from istrix.models.finding import Finding


class DnsProbeModule(ScanModule):
    """Discover AD topology and hostnames via DNS queries."""

    name = "dns_probe"
    description = "DNS PTR sweep + SRV queries for AD hostnames and forest topology"
    consumed_types = ["open_port", "service"]
    produced_types = ["dns", "os", "service"]
    optional = True

    _TIMEOUT = 3

    def run(self, findings: list[Finding]) -> list[Finding]:
        results: list[Finding] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        if not shutil.which("dig"):
            return results

        # Find DNS server and domain
        dns_server = ""
        domain = ""
        ip_pool: list[str] = []

        for f in findings:
            if f.type == "service" and f.port == 53:
                dns_server = f.host
            if f.type == "service":
                m = re.search(r'Domain:\s*(\S+)', f.detail or "")
                if m:
                    domain = m.group(1).rstrip(".,;0")
            if f.type == "open_port" and f.host:
                ip_pool.append(f.host)

        if not dns_server:
            return results

        # 1. SRV queries for DC discovery
        srv_queries = [
            ("_ldap._tcp", "LDAP servers"),
            ("_kerberos._tcp", "Kerberos servers (KDC)"),
            ("_gc._tcp", "Global Catalog servers"),
        ]
        for suffix, desc in srv_queries:
            if domain:
                full = f"{suffix}.{domain}"
                out = self._dig(dns_server, full, "SRV", short=True)
                hosts = sorted(set(re.findall(r'[\w.-]+\.[\w.-]+\.(?:[a-z]{2,})', out)))
                if hosts:
                    results.append(Finding(
                        type="dns", host=dns_server, port=53,
                        detail=f"AD {desc}: {', '.join(hosts)}",
                        source="dns_probe", timestamp=timestamp,
                    ))

        # 2. PTR sweep — resolve every scanned IP to hostname
        unique_ips = sorted(set(ip_pool), key=self._ip_sort_key)
        hostname_map: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(self._dig_ptr, dns_server, ip): ip for ip in unique_ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    hostname = future.result()
                    if hostname:
                        hostname_map[ip] = hostname
                except Exception:
                    pass

        if hostname_map:
            hostnames_str = ", ".join(
                f"{ip}→{h.split('.')[0]}" for ip, h in sorted(hostname_map.items())
            )
            results.append(Finding(
                type="dns", host=dns_server, port=53,
                detail=f"DNS PTR sweep: {len(hostname_map)} hosts: {hostnames_str[:500]}",
                source="dns_probe", timestamp=timestamp,
            ))

            for ip, hostname in hostname_map.items():
                short_name = hostname.split(".")[0]
                results.append(Finding(
                    type="os", host=ip, port=0,
                    detail=f"DNS: {short_name}",
                    source="dns_probe_ptr",
                    timestamp=timestamp,
                ))

        # 3. Cross-subnet DC resolution (from SRV results)
        dc_names = set()
        for f in results:
            if f.type == "dns" and f.source == "dns_probe":
                dc_names.update(re.findall(r'([\w-]+\.[\w.-]+\.[a-z]{2,})', f.detail))

        if dc_names and domain:
            # Resolve each discovered DC hostname to IP
            dc_results = []
            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = {ex.submit(self._dig, dns_server, dc, "A", short=True): dc for dc in dc_names}
                for future in as_completed(futures):
                    dc = futures[future]
                    try:
                        ip = future.result().strip()
                        if ip and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                            dc_results.append(f"{dc.split('.')[0]}→{ip}")
                    except Exception:
                        pass

            if dc_results:
                results.append(Finding(
                    type="dns", host=dns_server, port=53,
                    detail=f"DCs across subnets: {', '.join(sorted(dc_results))}",
                    source="dns_probe", timestamp=timestamp,
                ))

        return results

    # ── helpers ──────────────────────────────────────────────────────

    def _dig(self, server: str, name: str, rtype: str, short: bool = False) -> str:
        """Run dig query against the DNS server."""
        args = ["dig", f"@{server}", name, rtype, "+time=2", "+tries=1"]
        if short:
            args.append("+short")
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=self._TIMEOUT)
            return r.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            return ""

    def _dig_ptr(self, server: str, ip: str) -> str:
        """Reverse DNS lookup (PTR)."""
        args = ["dig", f"@{server}", "-x", ip, "+short", "+time=1", "+tries=1"]
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=2)
            entries = [line.rstrip(".") for line in r.stdout.strip().split("\n") if line and "." in line]
            return entries[0] if entries else ""
        except (subprocess.TimeoutExpired, OSError):
            return ""

    @staticmethod
    def _ip_sort_key(ip: str) -> tuple:
        try:
            parts = ip.split(".")
            return tuple(int(p) for p in parts)
        except (ValueError, AttributeError):
            return (999, 999, 999, 999)
