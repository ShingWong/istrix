"""Web directory brute-forcing module using Python stdlib HTTP/socket."""

import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import yaml

from istrix.engine.modules.base import ScanModule
from istrix.models.finding import Finding

_WEB_PATHS_PATH = Path(__file__).parent.parent.parent.parent / "config" / "web_paths.yaml"
_COMMON_PATHS_CACHE: list[str] | None = None


def _load_web_paths() -> list[str]:
    """Load common web paths from YAML config, with caching."""
    global _COMMON_PATHS_CACHE
    if _COMMON_PATHS_CACHE is not None:
        return _COMMON_PATHS_CACHE
    try:
        with open(_WEB_PATHS_PATH) as f:
            data = yaml.safe_load(f)
        paths = data.get("paths", []) if data else []
        _COMMON_PATHS_CACHE = [p for p in paths if isinstance(p, str)]
    except Exception:
        _COMMON_PATHS_CACHE = COMMON_PATHS_FALLBACK
    return _COMMON_PATHS_CACHE


COMMON_PATHS_FALLBACK = [
    "/", "/admin/", "/login/", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
    "/.git/", "/.env", "/backup/", "/config/", "/db/", "/mysql/",
    "/api/", "/api/v1/", "/graphql", "/swagger/", "/docs/", "/dev/",
    "/test/", "/staging/", "/debug/", "/.svn/", "/.htaccess",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/console/", "/actuator/", "/jmx-console/", "/web-console/",
    "/jenkins/", "/solr/", "/cgi-bin/", "/cgi/", "/shell/",
    "/upload/", "/uploads/", "/images/", "/img/", "/css/", "/js/",
    "/assets/", "/static/", "/public/", "/private/", "/tmp/", "/temp/",
    "/old/", "/new/", "/v1/", "/v2/", "/portal/", "/user/", "/users/",
    "/member/", "/members/", "/customer/", "/client/", "/clients/",
    "/vendor/", "/node_modules/", "/package.json", "/composer.json",
    "/.DS_Store", "/server-status", "/server-info", "/.well-known/",
    "/cpanel", "/webmail", "/mail/", "/owa/", "/ecp/",
    "/phpinfo.php", "/info.php", "/test.php", "/install/", "/setup/",
    "/readme.html", "/license.txt", "/changelog.txt",
    "/xmlrpc.php", "/wp-content/", "/wp-includes/",
    "/administrator/", "/bitrix/", "/sites/", "/moodle/",
    "/drupal/", "/joomla/", "/typo3/", "/magento/",
    "/.idea/", "/.vscode/", "/.circleci/", "/.travis.yml",
    "/.github/", "/.gitlab-ci.yml", "/Jenkinsfile",
    "/status", "/health", "/healthz", "/readyz", "/metrics",
    "/actuator/health", "/actuator/info", "/actuator/env",
]


class DirBustModule(ScanModule):
    """Basic directory brute-force for HTTP/HTTPS services using Python stdlib."""

    name = "dir_bust"
    description = "Brute-force common web directories on HTTP/HTTPS services"
    consumed_types = ["open_port", "service"]
    produced_types = ["web_tech"]
    optional = True

    def run(self, findings: list[Finding]) -> list[Finding]:
        results: list[Finding] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        web_targets = self._find_web_services(findings)

        if not web_targets:
            return results

        lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for host, port, use_ssl in web_targets:
                for path in _load_web_paths():
                    futures.append(
                        executor.submit(self._check_path, host, port, use_ssl,
                                        path, timestamp)
                    )

            for future in as_completed(futures):
                try:
                    finding = future.result()
                    if finding:
                        with lock:
                            results.append(finding)
                except Exception:
                    pass

        return results

    def _find_web_services(self, findings: list[Finding]) -> list[tuple[str, int, bool]]:
        seen: set[tuple[str, int]] = set()
        targets: list[tuple[str, int, bool]] = []

        for f in findings:
            if f.port is None:
                continue
            key = (f.host, f.port)
            if key in seen:
                continue

            detail_lower = f.detail.lower()
            is_http = any(s in detail_lower for s in
                          ("http", "https", "www", "http-proxy", "ssl/http"))
            if is_http:
                seen.add(key)
                use_ssl = (f.port in {443, 8443} or
                           "ssl" in detail_lower or "https" in detail_lower)
                targets.append((f.host, f.port, use_ssl))
            elif f.port in {80, 443, 8080, 8443, 8000, 8888, 3000, 5000,
                            9000, 9090, 9443}:
                seen.add(key)
                use_ssl = f.port in {443, 8443, 9443}
                targets.append((f.host, f.port, use_ssl))

        return targets

    def _check_path(self, host: str, port: int, use_ssl: bool, path: str,
                    timestamp: str) -> Finding | None:
        """Check if a single path exists on the target web service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))

            request = (
                f"GET {path} HTTP/1.0\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            sock.send(request)
            response = sock.recv(4096).decode(errors="ignore")
            sock.close()

            if not response:
                return None

            status_line = response.split("\r\n")[0] if "\r\n" in response else response
            status_code = 0
            parts = status_line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass

            if status_code in (200, 201, 202, 203, 204, 301, 302, 307, 308,
                               401, 403, 405, 500):
                scheme = "https" if use_ssl else "http"
                url = f"{scheme}://{host}:{port}{path}"

                return Finding(
                    type="web_tech",
                    host=host,
                    port=port,
                    protocol="tcp",
                    detail=f"{url} [{status_code}] {status_line[:150]}",
                    severity="info",
                    source="dir_bust",
                    evidence=response[:500],
                    timestamp=timestamp,
                )

            return None

        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
            return None
        except Exception:
            return None
