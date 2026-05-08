"""HTTP service probing module using whatweb or basic HTTP checks."""

import shutil
import socket
import subprocess
import ssl
from datetime import datetime, timezone

from istrix.engine.modules.base import ScanModule
from istrix.models.finding import Finding


class HTTPProbeModule(ScanModule):
    """Probe HTTP/HTTPS services for technology fingerprinting."""

    name = "http_probe"
    description = "Probe web services with whatweb or basic HTTP GET"
    consumed_types = ["open_port", "service"]
    produced_types = ["web_tech", "certificate"]
    optional = True

    HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000}
    HTTP_SERVICES = {"http", "https", "http-proxy", "ssl/http", "ssl/https", "www"}

    def run(self, findings: list[Finding]) -> list[Finding]:
        results: list[Finding] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        web_findings = [
            f for f in findings
            if self._is_web_service(f)
        ]

        use_whatweb = shutil.which("whatweb") is not None
        processed: set[str] = set()

        for f in web_findings:
            if f.port is None:
                continue
            key = f"{f.host}:{f.port}"
            if key in processed:
                continue
            processed.add(key)

            if use_whatweb:
                results.extend(self._run_whatweb(f, timestamp))
            else:
                results.extend(self._http_get_check(f, timestamp))

        return results

    def _is_web_service(self, finding: Finding) -> bool:
        """Check if a finding represents a potential web service."""
        if finding.port in self.HTTP_PORTS:
            return True
        detail_lower = finding.detail.lower()
        for svc in self.HTTP_SERVICES:
            if svc in detail_lower:
                return True
        return False

    def _build_url(self, host: str, port: int, use_ssl: bool) -> str:
        scheme = "https" if use_ssl or port == 443 else "http"
        return f"{scheme}://{host}:{port}"

    def _run_whatweb(self, finding: Finding, timestamp: str) -> list[Finding]:
        """Run whatweb against a web service."""
        if finding.port is None:
            return []

        use_ssl = finding.port in {443, 8443}
        url = self._build_url(finding.host, finding.port, use_ssl)
        results: list[Finding] = []

        try:
            result = subprocess.run(
                ["whatweb", "--no-errors", "--colour=never", url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout.strip()
            if output:
                lines = output.split("\n")
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if "https://" in line:
                        line = line.split("https://", 1)[1] if "https://" in line else line
                    else:
                        line = line.split("http://", 1)[1] if "http://" in line else line
                    if "] " in line:
                        line = line.split("] ", 1)[1]
                    results.append(Finding(
                        type="web_tech",
                        host=finding.host,
                        port=finding.port,
                        protocol="tcp",
                        detail=line[:200],
                        severity="info",
                        source="whatweb",
                        evidence=line[:500],
                        timestamp=timestamp,
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception:
            pass

        return results

    def _http_get_check(self, finding: Finding, timestamp: str) -> list[Finding]:
        """Fallback: basic socket check for HTTP response headers + Server extraction."""
        if finding.port is None:
            return []

        results: list[Finding] = []
        use_ssl = finding.port in {443, 8443}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=finding.host)
            sock.connect((finding.host, finding.port))

            server_header = ""
            if not use_ssl:
                sock.send(b"GET / HTTP/1.0\r\nHost: " + finding.host.encode() + b"\r\n\r\n")
                response = sock.recv(4096).decode(errors="ignore")
                first_line = response.split("\r\n")[0] if response else "No response"
                # Extract Server header for version detection
                for line in response.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server_header = line.split(":", 1)[1].strip()
                        break
            else:
                first_line = "HTTPS service (SSL)"
                cert = sock.getpeercert()
                if cert:
                    results.append(Finding(
                        type="certificate",
                        host=finding.host,
                        port=finding.port,
                        protocol="tcp",
                        detail=f"SSL cert subject: {cert.get('subject', 'unknown')}",
                        severity="info",
                        source="ssl_check",
                        timestamp=timestamp,
                    ))

            sock.close()

            results.append(Finding(
                type="web_tech",
                host=finding.host,
                port=finding.port,
                protocol="tcp",
                detail=f"HTTP response: {first_line[:200]}",
                severity="info",
                source="http_probe",
                timestamp=timestamp,
            ))

            # Record Server header as a version-detection finding
            if server_header:
                results.append(Finding(
                    type="service",
                    host=finding.host,
                    port=finding.port,
                    protocol="tcp",
                    detail=f"Server header: {server_header}",
                    severity="info",
                    source="http_probe",
                    evidence=server_header,
                    timestamp=timestamp,
                ))
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass

        return results
