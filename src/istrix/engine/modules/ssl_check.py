"""SSL/TLS certificate and cipher checking module using nmap ssl-* NSE scripts."""

import subprocess
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from istrix.engine.modules.base import ScanModule
from istrix.models.finding import Finding


class SSLCheckModule(ScanModule):
    """Check SSL/TLS services with nmap ssl-* NSE scripts."""

    name = "ssl_check"
    description = "Check SSL/TLS certs, ciphers, and known vulns (Heartbleed, POODLE)"
    consumed_types = ["open_port", "service"]
    produced_types = ["certificate", "vulnerability"]
    optional = True

    SSL_PORTS = {443, 8443, 465, 993, 995, 636, 989, 990, 6697}
    SSL_SERVICES = {"https", "ssl/http", "ssl/https", "ssl", "tls", "imaps", "pop3s",
                     "smtps", "ldaps", "ftps", "ircs"}

    def run(self, findings: list[Finding]) -> list[Finding]:
        results: list[Finding] = []
        timestamp = datetime.now(timezone.utc).isoformat()
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            return results

        ssl_targets = self._find_ssl_services(findings)

        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=8) as executor:
            future_map = {
                executor.submit(self._run_ssl_scripts, nmap_path, host, port, timestamp): (host, port)
                for host, port in ssl_targets
            }
            for future in as_completed(future_map):
                try:
                    host_results = future.result()
                    with lock:
                        results.extend(host_results)
                except Exception:
                    pass

        return results

    def _find_ssl_services(self, findings: list[Finding]) -> list[tuple[str, int]]:
        seen: set[tuple[str, int]] = set()
        targets: list[tuple[str, int]] = []

        for f in findings:
            if f.port is None:
                continue
            if f.port in self.SSL_PORTS:
                key = (f.host, f.port)
                if key not in seen:
                    seen.add(key)
                    targets.append(key)
                continue
            detail_lower = f.detail.lower()
            for svc in self.SSL_SERVICES:
                if svc in detail_lower:
                    key = (f.host, f.port)
                    if key not in seen:
                        seen.add(key)
                        targets.append(key)
                    break

        return targets

    def _run_ssl_scripts(self, nmap_path: str, host: str, port: int,
                         timestamp: str) -> list[Finding]:
        results: list[Finding] = []

        scripts = "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle"
        cmd = [nmap_path, "-oX", "-", "-sV", "--script", scripts,
               "-p", str(port), host]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=60)
        except subprocess.TimeoutExpired:
            return results

        if result.returncode != 0 and not result.stdout.strip():
            return results

        try:
            from istrix.engine.nmap import parse_nmap_xml
            nmap_findings = parse_nmap_xml(result.stdout, host)
            for f in nmap_findings:
                f.timestamp = timestamp
                f.port = port
                results.append(f)
        except Exception:
            pass

        return results
